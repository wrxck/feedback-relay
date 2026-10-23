import { X509Certificate } from 'node:crypto';

import { children, decodeOid, DerError, expectTag, readTlv, type Tlv, valueOf } from './der.js';

export const NONCE_EXTENSION_OID = '1.2.840.113635.100.8.2';

const SEQUENCE = 0x30;
const OCTET_STRING = 0x04;
const OID = 0x06;
const EXTENSIONS_TAG = 0xa3;
const NONCE_TAG = 0xa1;

export class ChainError extends Error {}

function isValidAt(cert: X509Certificate, now: Date): boolean {
  const from = Date.parse(cert.validFrom);
  const to = Date.parse(cert.validTo);
  return now.getTime() >= from && now.getTime() <= to;
}

// leaf <- intermediate <- pinned root, each signature checked and each certificate in date
export function verifyChain(x5c: Uint8Array[], rootPem: string, now: Date): X509Certificate {
  if (x5c.length !== 2) throw new ChainError('x5c must hold the leaf and one intermediate');
  const [leaf, intermediate] = x5c.map((der) => new X509Certificate(der)) as [
    X509Certificate,
    X509Certificate,
  ];
  const root = new X509Certificate(rootPem);
  if (!intermediate.ca || !root.ca) throw new ChainError('issuer is not a certificate authority');
  if (!leaf.checkIssued(intermediate) || !leaf.verify(intermediate.publicKey)) {
    throw new ChainError('leaf is not signed by the intermediate');
  }
  if (!intermediate.checkIssued(root) || !intermediate.verify(root.publicKey)) {
    throw new ChainError('intermediate is not signed by the apple root');
  }
  for (const cert of [leaf, intermediate, root]) {
    if (!isValidAt(cert, now)) throw new ChainError('a certificate in the chain is out of date');
  }
  return leaf;
}

function findExtension(der: Uint8Array, oid: string): Uint8Array | undefined {
  const cert = expectTag(readTlv(der, 0), SEQUENCE, 'certificate');
  const tbs = expectTag(children(der, cert)[0], SEQUENCE, 'tbs certificate');
  const wrapper = children(der, tbs).find((tlv) => tlv.tag === EXTENSIONS_TAG);
  if (!wrapper) return undefined;
  const list = expectTag(children(der, wrapper)[0], SEQUENCE, 'extensions');
  for (const extension of children(der, list)) {
    const parts: Tlv[] = children(der, expectTag(extension, SEQUENCE, 'extension'));
    const id = expectTag(parts[0], OID, 'extension id');
    if (decodeOid(valueOf(der, id)) !== oid) continue;
    return valueOf(der, expectTag(parts[parts.length - 1], OCTET_STRING, 'extension value'));
  }
  return undefined;
}

// the extension holds SEQUENCE { [1] EXPLICIT OCTET STRING nonce }
export function readNonceExtension(leafDer: Uint8Array): Uint8Array {
  try {
    const value = findExtension(leafDer, NONCE_EXTENSION_OID);
    if (!value) throw new ChainError('leaf has no app attest nonce extension');
    const sequence = expectTag(readTlv(value, 0), SEQUENCE, 'nonce sequence');
    const tagged = expectTag(children(value, sequence)[0], NONCE_TAG, 'nonce tag');
    const octets = expectTag(children(value, tagged)[0], OCTET_STRING, 'nonce octets');
    return valueOf(value, octets);
  } catch (error) {
    if (error instanceof DerError) throw new ChainError(`malformed leaf: ${error.message}`);
    throw error;
  }
}
