/**
 * CredSSP / TSRequest encoder+decoder (MS-CSSP §2.2)
 * Implements the full 5-step CredSSP flow with proper NTLM sealing.
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
import { RC4 } from './rc4';

// ── DER helpers ───────────────────────────────────────────────────────────

function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x100) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, (n >> 8) & 0xff, n & 0xff]);
}

function derTL(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}

function ctxConstructed(tag: number, content: Buffer): Buffer {
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

// ── NTLM Sealing Context (MS-NLMP §3.4) ──────────────────────────────────
// Maintains RC4 state across multiple seal() calls (seqNum 0, 1, 2, …)

export class SealingContext {
  private signKey: Buffer;
  private rc4:     RC4;
  private seqNum = 0;

  constructor(exportedSessionKey: Buffer) {
    this.signKey = crypto.createHmac('md5', exportedSessionKey)
      .update('session key to client-to-server signing key magic constant\0', 'ascii')
      .digest();
    const sealKey = crypto.createHmac('md5', exportedSessionKey)
      .update('session key to client-to-server sealing key magic constant\0', 'ascii')
      .digest();
    this.rc4 = new RC4(sealKey);
  }

  /**
   * SEAL(message) → 16-byte signature || encrypted message
   * The RC4 handle is shared across calls (seqNum increments each call).
   */
  seal(message: Buffer): Buffer {
    const seqBuf = Buffer.alloc(4);
    seqBuf.writeUInt32LE(this.seqNum++, 0);

    // 1. Encrypt the message (advances RC4 state)
    const encMsg = this.rc4.update(message);

    // 2. HMAC-MD5(signKey, seqNum || message)[:8], then encrypt checksum (continues RC4)
    const hmac = crypto.createHmac('md5', this.signKey)
      .update(seqBuf).update(message).digest();
    const encChecksum = this.rc4.update(hmac.slice(0, 8));

    // 3. Build 16-byte NTLMSSP_MESSAGE_SIGNATURE
    const sig = Buffer.alloc(16);
    sig.writeUInt32LE(1, 0);    // version = 1
    encChecksum.copy(sig, 4);   // 8 bytes encrypted checksum
    seqBuf.copy(sig, 12);       // 4 bytes seqNum

    return Buffer.concat([sig, encMsg]);
  }
}

// ── TSRequest builders ────────────────────────────────────────────────────

/** Step 1: Wrap NTLM Negotiate in TSRequest{version=6, negoTokens=[token]} */
export function buildTsRequestToken(token: Buffer): Buffer {
  const version   = ctxConstructed(0, derInteger(6));
  const negoToken = ctxConstructed(0, derOctetString(token));
  const negoItem  = derSequence(negoToken);
  const negoSeq   = derSequence(negoItem);
  const negoField = ctxConstructed(1, negoSeq);
  return derSequence(Buffer.concat([version, negoField]));
}

/** Step 3: TSRequest with NTLM Authenticate + sealed pubKeyAuth */
export function buildTsRequestAuth(token: Buffer, pubKeyAuth: Buffer): Buffer {
  const version   = ctxConstructed(0, derInteger(6));
  const negoToken = ctxConstructed(0, derOctetString(token));
  const negoItem  = derSequence(negoToken);
  const negoSeq   = derSequence(negoItem);
  const negoField = ctxConstructed(1, negoSeq);
  const pubKeyFld = ctxConstructed(3, derOctetString(pubKeyAuth));
  return derSequence(Buffer.concat([version, negoField, pubKeyFld]));
}

/** Step 5: TSRequest with authInfo = SEAL(TSCredentials) */
export function buildTsRequestAuthInfo(
  username: string, password: string, domain: string,
  ctx: SealingContext,
): Buffer {
  // TSPasswordCreds: domainName + userName + password (all UTF-16LE OCTET STRINGs)
  const domFld  = ctxConstructed(0, derOctetString(Buffer.from(domain,   'utf16le')));
  const usrFld  = ctxConstructed(1, derOctetString(Buffer.from(username, 'utf16le')));
  const pwFld   = ctxConstructed(2, derOctetString(Buffer.from(password, 'utf16le')));
  const tsCreds = derSequence(Buffer.concat([domFld, usrFld, pwFld]));

  // TSCredentials: credType=1 (password) + credentials
  const typeFld       = ctxConstructed(0, derInteger(1));
  const credFld       = ctxConstructed(1, derOctetString(tsCreds));
  const tsCredentials = derSequence(Buffer.concat([typeFld, credFld]));

  // Seal (encrypt + sign) the TSCredentials, seqNum continues from pubKeyAuth
  const sealedCreds = ctx.seal(tsCredentials);

  const version   = ctxConstructed(0, derInteger(6));
  const authField = ctxConstructed(2, derOctetString(sealedCreds));
  return derSequence(Buffer.concat([version, authField]));
}

// ── TSRequest parser ──────────────────────────────────────────────────────

export interface TsResponse {
  negoToken?: Buffer;
  errorCode?: number;
}

export function parseTsRequest(buf: Buffer): TsResponse {
  let i = 0;
  if (buf[i++] !== 0x30) return {};
  i += readDerLen(buf, i).consumed;
  const end = buf.length;

  while (i < end) {
    const tag = buf[i++];
    const { len, consumed } = readDerLen(buf, i);
    i += consumed;
    if (tag === 0xa1) {
      // negoTokens: SEQUENCE OF SEQUENCE { [0] OCTET STRING }
      let j = i;
      j++; j += readDerLen(buf, j).consumed; // outer SEQUENCE
      j++; j += readDerLen(buf, j).consumed; // inner SEQUENCE
      j++; j += readDerLen(buf, j).consumed; // [0] context
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
 * Compute CredSSP pubKeyAuth (step 3).
 * = SEAL(SubjectPublicKeyInfo from TLS server cert, seqNum=0)
 * Uses the SealingContext which is then reused for authInfo (seqNum=1).
 */
export function computePubKeyAuth(
  tlsSocket: tls.TLSSocket,
  ctx: SealingContext,
): Buffer {
  try {
    const cert = tlsSocket.getPeerCertificate();
    if (!cert?.raw) {
      console.warn('[credssp] No peer certificate found, sending empty pubKeyAuth');
      return Buffer.alloc(0);
    }
    // Extract SubjectPublicKeyInfo as DER using Node 15+ X509Certificate API
    const x509 = new crypto.X509Certificate(Buffer.from(cert.raw));
    const spki  = x509.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    return ctx.seal(spki);
  } catch (e) {
    console.error('[credssp] pubKeyAuth error:', e);
    return Buffer.alloc(0);
  }
}
