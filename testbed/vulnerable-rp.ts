/**
 * vulnerable-rp.ts — INTENTIONALLY INSECURE WebAuthn relying party.
 *
 * ⚠️  FOR TESTING PasskeyPwn ONLY. Serves on localhost. Do NOT deploy.
 *
 * It mimics a real RP's JSON ceremony API (webauthn.io / SimpleWebAuthn shape)
 * but deliberately OMITS several server-side validations so PasskeyPwn produces
 * real findings. What it still does correctly: stores the credential public key,
 * verifies the assertion signature, and looks up the credential by ID. What it
 * (insecurely) SKIPS:
 *   - origin check        → `origin` finding
 *   - challenge binding   → `challenge` (replay) finding
 *   - signature counter   → `counter` finding
 *   - UV flag enforcement → `flags` finding (policy says UV required)
 *   - attestation check   → `attestation` finding (policy requests "direct")
 *
 * Toggle individual flaws with env vars, e.g. PPWN_CHECK_ORIGIN=1.
 */

import { createServer } from 'node:http';
import { createHash, randomBytes, createPublicKey, verify as cryptoVerify, KeyObject } from 'node:crypto';
import { Decoder } from 'cbor-x';

const PORT = Number(process.env.PPWN_PORT ?? 8099);
const RP_ID = 'localhost';
const dec = new Decoder({ mapsAsObjects: false });

// Which checks are ENABLED (default: all insecure / disabled).
const CHECK = {
  origin: process.env.PPWN_CHECK_ORIGIN === '1',
  challenge: process.env.PPWN_CHECK_CHALLENGE === '1',
  counter: process.env.PPWN_CHECK_COUNTER === '1',
  uv: process.env.PPWN_CHECK_UV === '1',
  attestation: process.env.PPWN_CHECK_ATTESTATION === '1',
};

interface StoredCred { username: string; publicKey: KeyObject; signCount: number; }
const creds = new Map<string, StoredCred>();         // credId(b64url) -> cred
const byUser = new Map<string, string[]>();           // username -> credId(b64url)[]
const sessions = new Map<string, { challenge: string }>();

const b64url = (b: Buffer) => b.toString('base64url');
const sha256 = (d: Buffer) => createHash('sha256').update(d).digest();

function sid(cookie: string | undefined): string {
  const m = /ppwnsid=([^;]+)/.exec(cookie ?? '');
  if (m) return m[1]!;
  return randomBytes(16).toString('hex');
}

function readBody(req: any): Promise<any> {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c: Buffer) => (data += c));
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); }
    });
  });
}

function json(res: any, status: number, obj: unknown, setCookie?: string) {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (setCookie) headers['set-cookie'] = setCookie;
  res.writeHead(status, headers);
  res.end(JSON.stringify(obj));
}

/** Extract credentialId + EC public key from a registration attestationObject. */
function parseAttestation(attestationObject: Buffer): { credId: Buffer; publicKey: KeyObject } {
  const att = dec.decode(attestationObject) as Map<string, unknown>;
  const authData = att.get('authData') as Buffer;
  const credIdLen = authData.readUInt16BE(53);
  const credId = authData.subarray(55, 55 + credIdLen);
  const coseBytes = authData.subarray(55 + credIdLen);
  const cose = dec.decode(coseBytes) as Map<number, unknown>;
  const x = cose.get(-2) as Buffer;
  const y = cose.get(-3) as Buffer;
  const jwk = { kty: 'EC', crv: 'P-256', x: b64url(x), y: b64url(y) };
  const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
  return { credId: Buffer.from(credId), publicKey };
}

const server = createServer(async (req, res) => {
  const url = req.url ?? '/';
  const cookie = req.headers['cookie'] as string | undefined;

  if (req.method === 'GET' && (url === '/' || url.startsWith('/?'))) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(PAGE);
    return;
  }

  // ─── registration ───
  if (req.method === 'POST' && url === '/registration/options') {
    const body = await readBody(req);
    const id = sid(cookie);
    const challenge = b64url(randomBytes(32));
    sessions.set(id, { challenge });
    return json(res, 200, {
      challenge,
      rp: { id: RP_ID, name: 'PasskeyPwn Vulnerable RP' },
      user: { id: b64url(Buffer.from(body.username ?? 'user')), name: body.username, displayName: body.username },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60000,
      attestation: 'direct',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    }, `ppwnsid=${id}; Path=/; HttpOnly`);
  }

  if (req.method === 'POST' && url === '/registration/verification') {
    const body = await readBody(req);
    try {
      const attObj = Buffer.from(body.response.attestationObject, 'base64url');
      const clientData = JSON.parse(Buffer.from(body.response.clientDataJSON, 'base64url').toString('utf-8'));
      const id = sid(cookie);
      const sess = sessions.get(id);

      if (CHECK.origin && clientData.origin !== `http://localhost:${PORT}`) {
        return json(res, 400, { error: `Unexpected origin ${clientData.origin}` });
      }
      if (CHECK.challenge && (!sess || clientData.challenge !== sess.challenge)) {
        return json(res, 400, { error: 'Registration challenge mismatch' });
      }
      const att = dec.decode(attObj) as Map<string, unknown>;
      if (CHECK.attestation && att.get('fmt') === 'none') {
        return json(res, 400, { error: 'Attestation required but "none" provided' });
      }

      const { credId, publicKey } = parseAttestation(attObj);
      const credKey = b64url(credId);
      creds.set(credKey, { username: body.username, publicKey, signCount: 0 });
      byUser.set(body.username, [...(byUser.get(body.username) ?? []), credKey]);
      return json(res, 200, { verified: true });
    } catch (e) {
      return json(res, 400, { error: `Registration failed: ${(e as Error).message}` });
    }
  }

  // ─── authentication ───
  if (req.method === 'POST' && url === '/authentication/options') {
    const body = await readBody(req);
    const id = sid(cookie);
    const challenge = b64url(randomBytes(32));
    sessions.set(id, { challenge });
    const allow = (byUser.get(body.username) ?? []).map((cid) => ({ type: 'public-key', id: cid }));
    return json(res, 200, {
      challenge, rpId: RP_ID, timeout: 60000, userVerification: 'required',
      allowCredentials: allow,
    }, `ppwnsid=${id}; Path=/; HttpOnly`);
  }

  if (req.method === 'POST' && url === '/authentication/verification') {
    const body = await readBody(req);
    try {
      const r = body.response;
      const authData = Buffer.from(r.authenticatorData, 'base64url');
      const clientDataRaw = Buffer.from(r.clientDataJSON, 'base64url');
      const clientData = JSON.parse(clientDataRaw.toString('utf-8'));
      const sig = Buffer.from(r.signature, 'base64url');
      const credId = body.id ?? body.rawId;

      // Credential lookup (ENFORCED — not a planted flaw).
      const cred = creds.get(credId);
      if (!cred) return json(res, 400, { error: 'Unrecognized credential ID' });

      // Signature verification (ENFORCED).
      const signedData = Buffer.concat([authData, sha256(clientDataRaw)]);
      const sigOk = cryptoVerify('sha256', signedData, cred.publicKey, sig);
      if (!sigOk) return json(res, 400, { error: 'Invalid signature' });

      const id = sid(cookie);
      const sess = sessions.get(id);
      if (CHECK.origin && clientData.origin !== `http://localhost:${PORT}`) {
        return json(res, 400, { error: `Unexpected client data origin "${clientData.origin}"` });
      }
      if (CHECK.challenge && (!sess || clientData.challenge !== sess.challenge)) {
        return json(res, 400, { error: 'Client data challenge was not expected challenge' });
      }
      const flags = authData[32]!;
      if (CHECK.uv && (flags & 0x04) === 0) {
        return json(res, 400, { error: 'User verification required but UV flag not set' });
      }
      const newCount = authData.readUInt32BE(33);
      if (CHECK.counter && newCount !== 0 && newCount <= cred.signCount) {
        return json(res, 400, { error: `Sign count ${newCount} not greater than ${cred.signCount}` });
      }
      cred.signCount = newCount;
      return json(res, 200, { verified: true });
    } catch (e) {
      return json(res, 400, { error: `Authentication failed: ${(e as Error).message}` });
    }
  }

  res.writeHead(404);
  res.end('not found');
});

server.listen(PORT, () => {
  console.log(`[vuln-rp] ⚠️  INTENTIONALLY INSECURE WebAuthn RP on http://localhost:${PORT}`);
  console.log(`[vuln-rp] checks enabled: ${JSON.stringify(CHECK)}`);
});

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>PasskeyPwn Vulnerable RP</title></head>
<body style="font-family:sans-serif;max-width:520px;margin:40px auto">
<h2>PasskeyPwn — Vulnerable Test RP</h2>
<p style="color:#b91c1c">⚠️ Intentionally insecure. For testing only.</p>
<input id="username" placeholder="username" value="demo-user" style="padding:8px;width:100%;box-sizing:border-box">
<div style="margin-top:12px">
  <button id="register-button" style="padding:8px 16px">Register</button>
  <button id="authenticate-button" style="padding:8px 16px">Authenticate</button>
</div>
<div id="status" style="margin-top:16px;padding:10px;border:1px solid #ddd;min-height:20px"></div>
<script>
const b64urlToBuf = (s) => { const b = atob(s.replace(/-/g,'+').replace(/_/g,'/')); const u = new Uint8Array(b.length); for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i); return u.buffer; };
const bufToB64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=/g,'');
const status = (m, ok) => { const s=document.getElementById('status'); s.textContent=m; s.style.color = ok ? '#047857' : '#b91c1c'; };
async function post(u, b){ const r = await fetch(u,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}); return {status:r.status, json: await r.json().catch(()=>({}))}; }

document.getElementById('register-button').onclick = async () => {
  try {
    const username = document.getElementById('username').value;
    const o = (await post('/registration/options',{username})).json;
    o.challenge = b64urlToBuf(o.challenge); o.user.id = b64urlToBuf(o.user.id);
    const c = await navigator.credentials.create({publicKey:o});
    const body = { username, id:c.id, rawId:bufToB64url(c.rawId), type:c.type,
      response:{ clientDataJSON:bufToB64url(c.response.clientDataJSON), attestationObject:bufToB64url(c.response.attestationObject) } };
    const v = await post('/registration/verification', body);
    status(v.status===200 ? 'Registration success! Now authenticate.' : 'Registration failed: '+(v.json.error||v.status), v.status===200);
  } catch(e){ status('Registration error: '+e.message, false); }
};

document.getElementById('authenticate-button').onclick = async () => {
  try {
    const username = document.getElementById('username').value;
    const o = (await post('/authentication/options',{username})).json;
    o.challenge = b64urlToBuf(o.challenge);
    if (o.allowCredentials) o.allowCredentials.forEach(x=>x.id=b64urlToBuf(x.id));
    const c = await navigator.credentials.get({publicKey:o});
    const body = { username, id:c.id, rawId:bufToB64url(c.rawId), type:c.type,
      response:{ clientDataJSON:bufToB64url(c.response.clientDataJSON), authenticatorData:bufToB64url(c.response.authenticatorData),
        signature:bufToB64url(c.response.signature), userHandle:c.response.userHandle?bufToB64url(c.response.userHandle):null } };
    const v = await post('/authentication/verification', body);
    status(v.status===200 ? 'Authentication success!' : 'Authentication failed: '+(v.json.error||v.status), v.status===200);
  } catch(e){ status('Authentication error: '+e.message, false); }
};
</script></body></html>`;
