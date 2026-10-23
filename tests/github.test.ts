import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import { createGitHubIssueSink, GitHubError } from '../src/server/github.js';
import { githubAppJwt } from '../src/server/jwt.js';

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const draft = { title: '[Bug] x', body: 'b', labels: ['feedback'] };

function respond(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status });
}

function sinkWith(fetchMock: ReturnType<typeof vi.fn>, now = () => 1_700_000_000_000) {
  return createGitHubIssueSink({
    appId: '123',
    privateKey: pem,
    installationId: 456,
    owner: 'matt',
    repo: 'app',
    baseUrl: 'https://gh.test/',
    fetch: fetchMock as unknown as typeof fetch,
    now,
  });
}

const token = (expires: string) => respond(201, { token: 'ghs_x', expires_at: expires });
const created = () => respond(201, { number: 7, html_url: 'https://github.com/matt/app/issues/7' });

describe('githubAppJwt', () => {
  it('signs an rs256 jwt github accepts', () => {
    const jwt = githubAppJwt('123', pem, 1000);
    const [header, payload, signature] = jwt.split('.') as [string, string, string];
    expect(JSON.parse(Buffer.from(header, 'base64url').toString())).toEqual({
      alg: 'RS256',
      typ: 'JWT',
    });
    expect(JSON.parse(Buffer.from(payload, 'base64url').toString())).toEqual({
      iat: 940,
      exp: 1540,
      iss: '123',
    });
    const valid = verify(
      'sha256',
      Buffer.from(`${header}.${payload}`),
      createPublicKey(privateKey),
      Buffer.from(signature, 'base64url'),
    );
    expect(valid).toBe(true);
  });
});

describe('github issue sink', () => {
  it('exchanges a jwt for an installation token and creates the issue', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(token('2030-01-01T00:00:00Z'));
    fetchMock.mockResolvedValueOnce(created());
    const result = await sinkWith(fetchMock).createIssue(draft);
    expect(result).toEqual({ number: 7, url: 'https://github.com/matt/app/issues/7' });
    const [tokenUrl, tokenInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(tokenUrl).toBe('https://gh.test/app/installations/456/access_tokens');
    expect((tokenInit.headers as Record<string, string>).authorization).toMatch(/^Bearer ey/);
    const [issueUrl, issueInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(issueUrl).toBe('https://gh.test/repos/matt/app/issues');
    expect((issueInit.headers as Record<string, string>).authorization).toBe('Bearer ghs_x');
    expect(JSON.parse(issueInit.body as string)).toEqual(draft);
  });

  it('reuses a cached token until it nears expiry', async () => {
    let now = Date.parse('2030-01-01T00:00:00Z');
    const fetchMock = vi.fn().mockResolvedValueOnce(token('2030-01-01T01:00:00Z'));
    fetchMock.mockResolvedValueOnce(created()).mockResolvedValueOnce(created());
    fetchMock.mockResolvedValueOnce(token('2030-01-01T02:00:00Z')).mockResolvedValueOnce(created());
    const sink = sinkWith(fetchMock, () => now);
    await sink.createIssue(draft);
    await sink.createIssue(draft);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    now += 56 * 60 * 1000;
    await sink.createIssue(draft);
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  it('mints a fresh token once after a 401', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(token('2099-01-01T00:00:00Z'));
    fetchMock.mockResolvedValueOnce(respond(401, {}));
    fetchMock.mockResolvedValueOnce(token('2099-01-01T00:00:00Z')).mockResolvedValueOnce(created());
    expect((await sinkWith(fetchMock).createIssue(draft)).number).toBe(7);
  });

  it('raises a GitHubError on failure or malformed responses', async () => {
    const failing = vi.fn().mockResolvedValue(respond(403, {}));
    await expect(sinkWith(failing).createIssue(draft)).rejects.toThrow(GitHubError);
    const badToken = vi.fn().mockResolvedValue(respond(201, { token: 1 }));
    await expect(sinkWith(badToken).createIssue(draft)).rejects.toThrow(/malformed/);
    const badIssue = vi.fn().mockResolvedValueOnce(token('2099-01-01T00:00:00Z'));
    badIssue.mockResolvedValueOnce(respond(201, { number: 'x' }));
    await expect(sinkWith(badIssue).createIssue(draft)).rejects.toThrow(/malformed/);
  });

  it('defaults to api.github.com and global fetch', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(token('2099-01-01T00:00:00Z'));
    spy.mockResolvedValueOnce(created());
    const sink = createGitHubIssueSink({
      appId: '1',
      privateKey: pem,
      installationId: '2',
      owner: 'o',
      repo: 'r',
    });
    await sink.createIssue(draft);
    expect(spy.mock.calls[1]?.[0]).toBe('https://api.github.com/repos/o/r/issues');
    spy.mockRestore();
  });
});
