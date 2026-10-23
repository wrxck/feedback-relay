import type { IssueDraft } from './issue.js';
import { githubAppJwt } from './jwt.js';

export interface GitHubAppOptions {
  appId: string;
  privateKey: string;
  installationId: string | number;
  owner: string;
  repo: string;
  baseUrl?: string;
  fetch?: typeof fetch;
  now?: () => number;
}

export interface CreatedIssue {
  number: number;
  url: string;
}

export interface IssueSink {
  createIssue(draft: IssueDraft): Promise<CreatedIssue>;
}

export class GitHubError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

// refresh five minutes early so a token never expires between the cache check and the call
const REFRESH_MARGIN_MS = 5 * 60 * 1000;

function headers(token: string): Record<string, string> {
  return {
    accept: 'application/vnd.github+json',
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
    'user-agent': 'feedback-relay',
    'x-github-api-version': '2022-11-28',
  };
}

async function readJson(response: Response, what: string): Promise<Record<string, unknown>> {
  if (!response.ok)
    throw new GitHubError(`${what} failed with ${response.status}`, response.status);
  return (await response.json()) as Record<string, unknown>;
}

export function createGitHubIssueSink(options: GitHubAppOptions): IssueSink {
  const baseUrl = (options.baseUrl ?? 'https://api.github.com').replace(/\/+$/, '');
  const doFetch = options.fetch ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const repoPath = `${encodeURIComponent(options.owner)}/${encodeURIComponent(options.repo)}`;
  let cached: { token: string; expiresAt: number } | undefined;

  async function installationToken(): Promise<string> {
    if (cached && cached.expiresAt - REFRESH_MARGIN_MS > now()) return cached.token;
    const jwt = githubAppJwt(options.appId, options.privateKey, Math.floor(now() / 1000));
    const url = `${baseUrl}/app/installations/${encodeURIComponent(String(options.installationId))}/access_tokens`;
    const body = await readJson(
      await doFetch(url, { method: 'POST', headers: headers(jwt) }),
      'installation token',
    );
    const { token, expires_at: expiresAt } = body;
    if (typeof token !== 'string' || typeof expiresAt !== 'string') {
      throw new GitHubError('installation token response is malformed', 502);
    }
    cached = { token, expiresAt: Date.parse(expiresAt) };
    return token;
  }

  async function post(draft: IssueDraft): Promise<Response> {
    return doFetch(`${baseUrl}/repos/${repoPath}/issues`, {
      method: 'POST',
      headers: headers(await installationToken()),
      body: JSON.stringify(draft),
    });
  }

  return {
    async createIssue(draft) {
      let response = await post(draft);
      // a revoked or rotated token is refused once with 401; mint a fresh one and retry
      if (response.status === 401) {
        cached = undefined;
        response = await post(draft);
      }
      const body = await readJson(response, 'create issue');
      if (typeof body.number !== 'number' || typeof body.html_url !== 'string') {
        throw new GitHubError('create issue response is malformed', 502);
      }
      return { number: body.number, url: body.html_url };
    },
  };
}
