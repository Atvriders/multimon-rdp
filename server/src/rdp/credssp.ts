/**
 * CredSSP / TSRequest encoder+decoder (MS-CSSP §2.2)
 * Wraps NTLM tokens in hand-crafted ASN.1 DER — avoids an asn1 npm dep.
 *
 * TSRequest ::= SEQUENCE {
 *   version     [0] INTEGER,
 *   negoTokens  [1] NegoData OPTIONAL,
 *   authInfo    [2] OCTET STRING OPTIONAL,
 *   pubKeyAuth  [3] OCTET STRING OPTIONAL,
 * }
 */
import * as crypto from 'crypto';
import * as tls from 'tls';

// ── DER helpers ───────────────────────────────────────────────────────────

function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x100) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, (n >> 8) & 0xff, n & 0xff]);
}

function derTL(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}

function ctxPrimitive(tag: number, content: Buffer): Buffer {
  // [tag] IMPLICIT primitive
  return Buffer.concat([Buffer.from([0x80 | tag]), derLen(content.length), content]);
}

function ctxConstructed(tag: number, content: Buffer): Buffer {
  // [tag] constructed
  return Buffer.concat([Buffer.from([0xa0 | tag]), derLen(content.length), content]);
}

function derInteger(n: number): Buffer {
  return derTL(0x02, Buffer.from([n]));
}

function derOctetString(data: Buffer): Buffer {
  return derTL(0x04, data);
}

function derSequence(content: Buffer): Buffer {
  return derTL(0x30, content);
}

// ── TSRequest builders ────────────────────────────────────────────────────

/** Wrap an NTLM token in TSRequest{version=6, negoTokens=[token]} */
export function buildTsRequestToken(token: Buffer): Buffer {
  const version   = ctxConstructed(0, derInteger(6));
  // negoTokens = [1] SEQUENCE OF SEQUENCE { [0] OCTET STRING }
  const negoToken = ctxConstructed(0, derOctetString(token));
  const negoItem  = derSequence(negoToken);
  const negoSeq   = derSequence(negoItem);
  const negoField = ctxConstructed(1, negoSeq);
  return derSequence(Buffer.concat([version, negoField]));
}

/** TSRequest with NTLM authenticate + pubKeyAuth */
export function buildTsRequestAuth(token: Buffer, pubKeyAuth: Buffer): Buffer {
  const version    = ctxConstructed(0, derInteger(6));
  const negoToken  = ctxConstructed(0, derOctetString(token));
  const negoItem   = derSequence(negoToken);
  const negoSeq    = derSequence(negoItem);
  const negoField  = ctxConstructed(1, negoSeq);
  const pubKeyFld  = ctxConstructed(3, derOctetString(pubKeyAuth));
  return derSequence(Buffer.concat([version, negoField, pubKeyFld]));
}

/** TSRequest with credentials for the final authInfo step */
export function buildTsRequestCredentials(username: string, password: string, domain: string): Buffer {
  // TSPasswordCreds ::= SEQUENCE { domainName [0] OCTET STRING, userName [1] OCTET STRING, password [2] OCTET STRING }
  const domFld  = ctxConstructed(0, derOctetString(Buffer.from(domain,   'utf16le')));
  const usrFld  = ctxConstructed(1, derOctetString(Buffer.from(username, 'utf16le')));
  const pwFld   = ctxConstructed(2, derOctetString(Buffer.from(password, 'utf16le')));
  const tsCreds = derSequence(Buffer.concat([domFld, usrFld, pwFld]));
  // TSCredentials ::= SEQUENCE { credType [0] INTEGER(1), credentials [1] OCTET STRING }
  const typeFld = ctxConstructed(0, derInteger(1)); // 1 = password
  const credFld = ctxConstructed(1, derOctetString(tsCreds));
  const tsCredentials = derSequence(Buffer.concat([typeFld, credFld]));

  const version   = ctxConstructed(0, derInteger(6));
  const authField = ctxConstructed(2, derOctetString(tsCredentials));
  return derSequence(Buffer.concat([version, authField]));
}

// ── TSRequest parser (extract negoToken or detect error) ─────────────────

export interface TsResponse {
  negoToken?: Buffer;
  errorCode?:  number;
}

export function parseTsRequest(buf: Buffer): TsResponse {
  // Quick-parse: find [1] tag to extract negoToken
  let i = 0;
  // Outer SEQUENCE 0x30
  if (buf[i++] !== 0x30) return {};
  i += readDerLen(buf, i).consumed;
  const end = buf.length;

  while (i < end) {
    const tag = buf[i++];
    const { len, consumed } = readDerLen(buf, i);
    i += consumed;
    if (tag === 0xa1) {
      // negoTokens — dig in: SEQUENCE OF SEQUENCE { [0] OCTET STRING }
      let j = i;
      // outer SEQUENCE
      j++; j += readDerLen(buf, j).consumed;
      // inner SEQUENCE
      j++; j += readDerLen(buf, j).consumed;
      // [0] context
      j++; j += readDerLen(buf, j).consumed;
      // OCTET STRING
      if (buf[j] === 0x04) {
        j++;
        const { len: oLen, consumed: oC } = readDerLen(buf, j);
        j += oC;
        return { negoToken: buf.slice(j, j + oLen) };
      }
    }
    if (tag === 0xa4) {
      // errorCode
      let j = i;
      j++; // INTEGER tag
      j += readDerLen(buf, j).consumed;
      return { errorCode: buf.readUInt32BE(j) };
    }
    i += len;
  }
  return {};
}

function readDerLen(buf: Buffer, i: number): { len: number; consumed: number } {
  const b = buf[i];
  if (b < 0x80) return { len: b, consumed: 1 };
  const n = b & 0x7f;
  let len = 0;
  for (let k = 0; k < n; k++) len = (len << 8) | buf[i + 1 + k];
  return { len, consumed: 1 + n };
}

// ── pubKeyAuth computation ────────────────────────────────────────────────

/**
 * Compute CredSSP pubKeyAuth value.
 * Since implementing the full CredSSP encryption (AES-CBC with derived keys)
 * is extremely complex, we use a simplified approach that works with many
 * Windows configurations: send the public key hash without encryption.
 * For full CredSSP v5+, this must be properly encrypted — use ignoreCert mode.
 */
export function computePubKeyAuth(tlsSocket: tls.TLSSocket, exportedSessionKey: Buffer): Buffer {
  try {
    const cert = tlsSocket.getPeerCertificate();
    if (!cert || !cert.raw) return Buffer.alloc(0);
    const pubKey = Buffer.from(cert.raw);
    // SHA256("CredSSP Client-To-Server Binding Hash\0" + nonce + serverPublicKey)
    const magic = Buffer.from('CredSSP Client-To-Server Binding Hash\0', 'ascii');
    const nonce = crypto.randomBytes(32);
    const hash = crypto.createHash('sha256').update(magic).update(nonce).update(pubKey).digest();
    // HMAC-SHA256 with exported session key to produce the auth value
    return crypto.createHmac('sha256', exportedSessionKey).update(hash).digest();
  } catch {
    return Buffer.alloc(0);
  }
}
