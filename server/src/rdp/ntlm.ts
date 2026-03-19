/**
 * NTLMv2 authentication implementation (MS-NLMP)
 * Used by CredSSP/NLA to authenticate against Windows RDP.
 */
import * as crypto from 'crypto';
import { md4 } from './md4';
import { RC4 } from './rc4';

// ── Helpers ──────────────────────────────────────────────────────────────────

function hmacMD5(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac('md5', key).update(data).digest();
}

function ntHash(password: string): Buffer {
  return md4(Buffer.from(password, 'utf16le'));
}

function ntlmv2Hash(ntH: Buffer, username: string, domain: string): Buffer {
  const msg = Buffer.from(username.toUpperCase() + domain, 'utf16le');
  return hmacMD5(ntH, msg);
}

// Windows FILETIME = microseconds since 1601-01-01, as 100ns intervals
function fileTime(): Buffer {
  const buf = Buffer.alloc(8);
  const unix_ms = BigInt(Date.now());
  const ft = unix_ms * 10000n + 116444736000000000n;
  buf.writeBigUInt64LE(ft);
  return buf;
}

// ── NTLM Negotiate (Type 1) ───────────────────────────────────────────────

const NEG_FLAGS =
  0x60088215 | // UNICODE + OEM + REQUEST_TARGET + NTLM + EXTENDED_SESSIONSECURITY
  0x02000000 | // VERSION
  0x20000000 | // NEGOTIATE_128
  0x40000000 | // KEY_EXCH
  0x80000000;  // NEGOTIATE_56

export function buildNegotiate(): Buffer {
  const buf = Buffer.alloc(40);
  buf.write('NTLMSSP\0', 0, 'ascii');
  buf.writeUInt32LE(1, 8);               // MessageType
  buf.writeUInt32LE(NEG_FLAGS >>> 0, 12); // NegotiateFlags
  // Domain / Workstation fields: empty (offset=40, len=0)
  buf.writeUInt16LE(0, 16); buf.writeUInt16LE(0, 18); buf.writeUInt32LE(40, 20);
  buf.writeUInt16LE(0, 24); buf.writeUInt16LE(0, 26); buf.writeUInt32LE(40, 28);
  // Version: 6.1.7601, NTLMRevisionCurrent=15
  buf.writeUInt8(6, 32); buf.writeUInt8(1, 33);
  buf.writeUInt16LE(7601, 34); buf.writeUInt8(15, 39);
  return buf;
}

// ── NTLM Challenge (Type 2) parser ───────────────────────────────────────

export interface NtlmChallenge {
  serverChallenge: Buffer;
  targetInfo:      Buffer;
  flags:           number;
}

export function parseChallenge(buf: Buffer): NtlmChallenge {
  if (buf.toString('ascii', 0, 8) !== 'NTLMSSP\0') throw new Error('Bad NTLM signature');
  if (buf.readUInt32LE(8) !== 2) throw new Error('Expected NTLM type 2');
  const flags           = buf.readUInt32LE(20);
  const serverChallenge = buf.slice(24, 32);
  const tiLen           = buf.readUInt16LE(40);
  const tiOff           = buf.readUInt32LE(44);
  const targetInfo      = buf.slice(tiOff, tiOff + tiLen);
  return { serverChallenge, targetInfo, flags };
}

// ── NTLM Authenticate (Type 3) ───────────────────────────────────────────

export interface AuthResult {
  msg:            Buffer;
  exportedSession: Buffer;  // used by CredSSP for pubKeyAuth
}

export function buildAuthenticate(
  username: string,
  password: string,
  domain:   string,
  ch:       NtlmChallenge,
  negotiateMsg: Buffer,
  challengeMsg: Buffer,
): AuthResult {
  const ntH   = ntHash(password);
  const ntv2H = ntlmv2Hash(ntH, username, domain);

  // Build NTLMv2 client blob
  const clientChallenge = crypto.randomBytes(8);
  const ts              = fileTime();
  const blobHdr = Buffer.from([0x01,0x01,0x00,0x00, 0x00,0x00,0x00,0x00]);
  const trailingNull = Buffer.alloc(4);
  const blob = Buffer.concat([blobHdr, ts, clientChallenge, Buffer.alloc(4), ch.targetInfo, trailingNull]);

  const NTProofStr = hmacMD5(ntv2H, Buffer.concat([ch.serverChallenge, blob]));
  const ntResponse = Buffer.concat([NTProofStr, blob]);

  // Session key derivation
  const sessionBaseKey     = hmacMD5(ntv2H, NTProofStr);
  const exportedSessionKey = crypto.randomBytes(16);
  // RC4 encrypt the exported session key (pure-JS to avoid OpenSSL 3 legacy issues)
  const encSessionKey = new RC4(sessionBaseKey).update(exportedSessionKey);

  const domainBuf   = Buffer.from(domain,   'utf16le');
  const userBuf     = Buffer.from(username, 'utf16le');
  const workBuf     = Buffer.from('',       'utf16le');
  const lmResponse  = Buffer.alloc(24, 0);

  const HEADER = 88; // fixed header bytes (includes 16-byte MIC slot)
  let off = HEADER;
  const lmOff  = off; off += lmResponse.length;
  const ntOff  = off; off += ntResponse.length;
  const domOff = off; off += domainBuf.length;
  const usrOff = off; off += userBuf.length;
  const wsOff  = off; off += workBuf.length;
  const skOff  = off; off += encSessionKey.length;

  const msg = Buffer.alloc(off);
  msg.write('NTLMSSP\0', 0, 'ascii');
  msg.writeUInt32LE(3, 8);
  msg.writeUInt16LE(lmResponse.length, 12); msg.writeUInt16LE(lmResponse.length, 14); msg.writeUInt32LE(lmOff,  16);
  msg.writeUInt16LE(ntResponse.length, 20); msg.writeUInt16LE(ntResponse.length, 22); msg.writeUInt32LE(ntOff,  24);
  msg.writeUInt16LE(domainBuf.length, 28);  msg.writeUInt16LE(domainBuf.length, 30);  msg.writeUInt32LE(domOff, 32);
  msg.writeUInt16LE(userBuf.length, 36);    msg.writeUInt16LE(userBuf.length, 38);    msg.writeUInt32LE(usrOff, 40);
  msg.writeUInt16LE(workBuf.length, 44);    msg.writeUInt16LE(workBuf.length, 46);    msg.writeUInt32LE(wsOff,  48);
  msg.writeUInt16LE(encSessionKey.length, 52); msg.writeUInt16LE(encSessionKey.length, 54); msg.writeUInt32LE(skOff, 56);
  msg.writeUInt32LE(NEG_FLAGS >>> 0, 60);
  msg.writeUInt8(6, 64); msg.writeUInt8(1, 65); msg.writeUInt16LE(7601, 66); msg.writeUInt8(15, 71);
  // MIC at offset 72-87 — compute after filling payload
  lmResponse.copy(msg, lmOff);
  ntResponse.copy(msg, ntOff);
  domainBuf.copy(msg, domOff);
  userBuf.copy(msg, usrOff);
  workBuf.copy(msg, wsOff);
  encSessionKey.copy(msg, skOff);

  // Compute MIC = HMAC-MD5(exportedSessionKey, negotiate + challenge + authenticate_with_zeroed_mic)
  const mic = hmacMD5(exportedSessionKey, Buffer.concat([negotiateMsg, challengeMsg, msg]));
  mic.copy(msg, 72);

  return { msg, exportedSession: exportedSessionKey };
}
