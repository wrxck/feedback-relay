export interface VerifyInput {
  // the verifier-specific object the client's AttestProvider produced
  proof: Record<string, unknown>;
  // the exact bytes the proof must cover: protocol version, challenge and payload hash
  clientData: Uint8Array;
  ip: string | undefined;
}

export type VerifyResult =
  { ok: true; subject: string } | { ok: false; code: 'unverified' | 'unknown_key'; reason: string };

// one way to prove a request came from the genuine app; subject keys the per-client rate limit
export interface Verifier {
  readonly name: string;
  verify(input: VerifyInput): Promise<VerifyResult>;
}
