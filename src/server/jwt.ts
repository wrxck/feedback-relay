import { createPrivateKey, sign } from 'node:crypto';

import { toBase64Url } from '../shared/base64.js';

function segment(value: object): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

// github accepts at most ten minutes; iat is backdated a minute for clock drift
export function githubAppJwt(appId: string, privateKeyPem: string, nowSeconds: number): string {
  const header = segment({ alg: 'RS256', typ: 'JWT' });
  const payload = segment({ iat: nowSeconds - 60, exp: nowSeconds + 9 * 60, iss: appId });
  const input = `${header}.${payload}`;
  const signature = sign(
    'sha256',
    new TextEncoder().encode(input),
    createPrivateKey(privateKeyPem),
  );
  return `${input}.${toBase64Url(new Uint8Array(signature))}`;
}
