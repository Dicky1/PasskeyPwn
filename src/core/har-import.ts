import { readFileSync } from 'node:fs';
import { CeremonyTranscript, CapturedRequest } from './replay.js';

export function loadHarTranscript(harPath: string): CeremonyTranscript {
  const raw = JSON.parse(readFileSync(harPath, 'utf-8'));
  const entries = (raw?.log?.entries ?? []) as any[];
  const posts: CapturedRequest[] = entries
    .filter((e) => e?.request?.method === 'POST')
    .map((e) => ({
      url: e.request.url,
      method: e.request.method,
      headers: Object.fromEntries((e.request.headers ?? []).map((h: any) => [h.name, h.value])),
      body: e.request.postData?.text ?? null,
    }));
  const finish = [...posts].reverse().find((p) => p.body && /clientdata|signature|authenticator/i.test(p.body)) ?? posts[posts.length - 1]!;
  const options = posts.find((p) => p !== finish) ?? null;
  let rpId = '';
  try { rpId = new URL(finish.url).hostname; } catch {}
  return { rpId, origin: new URL(finish.url).origin, optionsRequest: options, finishRequest: finish };
}