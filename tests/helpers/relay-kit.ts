import { createHash } from 'node:crypto';

import { clientDataFor } from '../../src/shared/protocol.js';
import type { IssueDraft } from '../../src/server/issue.js';
import type { IssueSink } from '../../src/server/github.js';
import type { Verifier } from '../../src/server/verifier.js';

export function recordingSink(fail = false): IssueSink & { drafts: IssueDraft[] } {
  const drafts: IssueDraft[] = [];
  return {
    drafts,
    createIssue(draft) {
      if (fail) return Promise.reject(new Error('github down'));
      drafts.push(draft);
      return Promise.resolve({
        number: drafts.length,
        url: `https://example.test/${drafts.length}`,
      });
    },
  };
}

// accepts a proof whose token equals the client data, so tests can forge or tamper deliberately
export const echoVerifier: Verifier = {
  name: 'echo',
  verify({ proof, clientData }) {
    const expected = new TextDecoder().decode(clientData);
    return Promise.resolve(
      proof.token === expected
        ? { ok: true, subject: typeof proof.subject === 'string' ? proof.subject : 'device' }
        : { ok: false, code: 'unverified', reason: 'token mismatch' },
    );
  },
};

export function clientDataOf(challenge: string, payload: string): string {
  return clientDataFor(challenge, new Uint8Array(createHash('sha256').update(payload).digest()));
}
