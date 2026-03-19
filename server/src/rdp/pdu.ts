/**
 * RDP PDU builders and parsers.
 * Covers: TPKT, X.224, MCS, RDP slow-path and fast-path frames.
 */

// ── TPKT (RFC 1006 / ISO 8073) ───────────────────────────────────────────

export function tpkt(payload: Buffer): Buffer {
  const buf = Buffer.alloc(4 + payload.length);
  buf[0] = 3; buf[1] = 0;
  buf.writeUInt16BE(buf.length, 2);
  payload.copy(buf, 4);
  return buf;
}

export function parseTpktLen(buf: Buffer): number {
  if (buf.length < 4) return 0;
  if (buf[0] !== 3) return -1; // not TPKT
  return buf.readUInt16BE(2);
}

// ── X.224 ────────────────────────────────────────────────────────────────

export const PROTO_RDP    = 0;
export const PROTO_TLS    = 1;
export const PROTO_HYBRID = 2; // NLA / CredSSP

/** X.224 Connection Request — requests NLA/TLS */
export function x224ConnectReq(requestedProtocols: number): Buffer {
  const negReq = Buffer.alloc(8);
  negReq[0] = 0x01;               // type = RDP_NEG_REQ
  negReq[1] = 0x00;               // flags
  negReq.writeUInt16LE(8, 2);    // length
  negReq.writeUInt32LE(requestedProtocols, 4);
  const tpdu = Buffer.alloc(7 + negReq.length);
  tpdu[0] = tpdu.length - 1; // LI
  tpdu[1] = 0xE0;            // CR CDT
  tpdu.writeUInt16BE(0, 2);  // dst-ref
  tpdu.writeUInt16BE(0, 4);  // src-ref
  tpdu[6] = 0x00;            // class
  negReq.copy(tpdu, 7);
  return tpkt(tpdu);
}

/** Parse X.224 Connection Confirm → selected protocol */
export function parseX224CC(buf: Buffer): number {
  // [4] = TPKT payload start; skip LI+CC+dst+src+class = 7 bytes; then RDP_NEG_RSP
  const off = 4 + 7; // tpkt header + x224 fixed header
  if (buf.length < off + 8) return PROTO_RDP;
  if (buf[off] !== 0x02) return PROTO_RDP; // RDP_NEG_RSP
  return buf.readUInt32LE(off + 4);
}

/** X.224 data TPDU wrapping an MCS/RDP payload */
export function x224Data(payload: Buffer): Buffer {
  return tpkt(Buffer.concat([Buffer.from([0x02, 0xF0, 0x80]), payload]));
}

/** Strip the X.224 data header from a received TPKT frame */
export function stripX224(tpktBuf: Buffer): Buffer {
  return tpktBuf.slice(7); // 4 TPKT + 3 X224-data
}

// ── BER integer helpers (for MCS ASN.1) ──────────────────────────────────

function berLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x100) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, (n >> 8) & 0xff, n & 0xff]);
}

function berInt(val: number, bytes = 2): Buffer {
  // Primitive INTEGER
  const v = Buffer.alloc(bytes);
  if (bytes === 2) v.writeUInt16BE(val);
  else if (bytes === 1) v[0] = val;
  return Buffer.concat([Buffer.from([0x02]), berLen(bytes), v]);
}

function berSeq(content: Buffer, appTag?: number): Buffer {
  const tag = appTag !== undefined ? (0x60 | appTag) : 0x30;
  return Buffer.concat([Buffer.from([tag]), berLen(content.length), content]);
}

function berOctet(data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x04]), berLen(data.length), data]);
}

function berBool(val: boolean): Buffer {
  return Buffer.from([0x01, 0x01, val ? 0xff : 0x00]);
}

// ── MCS params ────────────────────────────────────────────────────────────

function mcsParams(maxCh: number, maxUser: number, maxToken: number, maxMcs: number): Buffer {
  return berSeq(Buffer.concat([
    berInt(maxCh), berInt(maxUser), berInt(maxToken),
    berInt(1), berInt(0), berInt(1), berInt(maxMcs), berInt(2),
  ]));
}

// ── GCC / RDP User Data blocks ───────────────────────────────────────────

function udBlock(type: number, data: Buffer): Buffer {
  const hdr = Buffer.alloc(4);
  hdr.writeUInt16LE(type, 0);
  hdr.writeUInt16LE(data.length + 4, 2);
  return Buffer.concat([hdr, data]);
}

/** TS_UD_CS_CORE */
export function udCSCore(width: number, height: number): Buffer {
  const d = Buffer.alloc(212);
  d.writeUInt32LE(0x00080004, 0);  // RDP 5.0
  d.writeUInt16LE(width,  4);
  d.writeUInt16LE(height, 6);
  d.writeUInt16LE(0xCA01, 8);      // colorDepth = COLOR_8BPP
  d.writeUInt16LE(0xAA03, 10);     // SASSequence
  d.writeUInt32LE(0x0409, 12);     // keyboardLayout (EN-US)
  d.writeUInt32LE(0x0A28, 16);     // clientBuild
  Buffer.from('rdp-client\0', 'utf16le').copy(d, 20);  // clientName (32 bytes)
  d.writeUInt32LE(4, 52);          // keyboardType (IBM 101)
  d.writeUInt32LE(0, 56);
  d.writeUInt32LE(12, 60);         // keyboardFunctionKey
  // imeFileName: 64 zeros (offset 64)
  d.writeUInt16LE(0xCA01, 128);    // postBeta2ColorDepth
  d.writeUInt16LE(1, 130);         // clientProductId
  d.writeUInt32LE(0, 132);         // serialNumber
  d.writeUInt16LE(0x0020, 136);    // highColorDepth = 32bpp
  d.writeUInt16LE(0x000F, 138);    // supportedColorDepths (all)
  d.writeUInt16LE(0x0061, 140);    // earlyCapabilityFlags
  // clientDigProductId: 64 zeros (offset 142)
  d.writeUInt8(0x06, 206);         // connectionType = AUTODETECT
  d.writeUInt8(0x00, 207);         // pad
  d.writeUInt32LE(PROTO_HYBRID, 208); // serverSelectedProtocol
  return udBlock(0xC001, d);
}

/** TS_UD_CS_SEC — no encryption (TLS handles it) */
export function udCSSec(): Buffer {
  const d = Buffer.alloc(8);
  d.writeUInt32LE(0, 0); // encryptionMethods = NONE
  d.writeUInt32LE(0, 4);
  return udBlock(0xC002, d);
}

/** TS_UD_CS_NET — minimal channel list */
export function udCSNet(): Buffer {
  const channels: { name: string; options: number }[] = [
    { name: 'rdpsnd\0\0', options: 0x00000000 },
    { name: 'cliprdr\0', options: 0xC0A00000 },
  ];
  const d = Buffer.alloc(4 + channels.length * 12);
  d.writeUInt32LE(channels.length, 0);
  channels.forEach((ch, i) => {
    Buffer.from(ch.name, 'ascii').copy(d, 4 + i * 12);
    d.writeUInt32LE(ch.options, 4 + i * 12 + 8);
  });
  return udBlock(0xC003, d);
}

/** TS_UD_CS_CLUSTER */
export function udCSCluster(): Buffer {
  const d = Buffer.alloc(12);
  d.writeUInt32LE(0x0d, 0);  // REDIRECTION_SUPPORTED | SERVER_SESSION_REDIRECTION_VERSION_MASK=3
  d.writeUInt32LE(0, 4);
  return udBlock(0xC004, d);
}

/** TS_UD_CS_MONITOR — multi-monitor layout */
export function udCSMonitor(monitorCount: number, monitorWidth: number, monitorHeight: number): Buffer {
  const d = Buffer.alloc(8 + monitorCount * 20);
  d.writeUInt32LE(0, 0);            // flags
  d.writeUInt32LE(monitorCount, 4); // monitorCount
  for (let i = 0; i < monitorCount; i++) {
    const off = 8 + i * 20;
    d.writeInt32LE(i * monitorWidth, off);              // left
    d.writeInt32LE(0,                 off + 4);          // top
    d.writeInt32LE((i + 1) * monitorWidth, off + 8);    // right (exclusive)
    d.writeInt32LE(monitorHeight,     off + 12);         // bottom (exclusive)
    d.writeUInt32LE(i === 0 ? 1 : 0, off + 16);         // flags: 1=PRIMARY
  }
  return udBlock(0xC005, d);
}

// ── GCC Conference Create Request ─────────────────────────────────────────

function gccCCrq(userData: Buffer): Buffer {
  // T.124 GCC header (7 bytes): object key for RDP GCC
  const hdr  = Buffer.from([0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01]);
  // Conference descriptor (8 bytes) — minimal GCC conference name
  const tail = Buffer.from([0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00]);
  // PER length = bytes that follow: tail(8) + userData
  return Buffer.concat([hdr, encodePER14(tail.length + userData.length), tail, userData]);
}

function encodePER14(n: number): Buffer {
  // PER aligned length field (14-bit max for short form)
  const buf = Buffer.alloc(2);
  buf.writeUInt16BE(0x8000 | (n & 0x3fff), 0);
  return buf;
}

// ── MCS Connect-Initial ───────────────────────────────────────────────────

export function mcsConnectInitial(
  width: number, height: number,
  monitorCount: number, monitorWidth: number, monitorHeight: number,
): Buffer {
  const totalW = monitorWidth * monitorCount;
  const udBlocks = Buffer.concat([
    udCSCore(totalW, monitorHeight),
    udCSSec(),
    udCSNet(),
    udCSCluster(),
    ...(monitorCount > 1 ? [udCSMonitor(monitorCount, monitorWidth, monitorHeight)] : []),
  ]);

  const gccData = gccCCrq(udBlocks);
  const userData = berOctet(gccData);

  const target  = mcsParams(34, 3, 0, 65535);
  const minimum = mcsParams(1, 1, 1, 1056);
  const maximum = mcsParams(65535, 64520, 65535, 65535);

  const ci = berSeq(Buffer.concat([
    berOctet(Buffer.from([0x01])),  // callingDomainSelector
    berOctet(Buffer.from([0x01])),  // calledDomainSelector
    berBool(true),                  // upwardFlag
    target, minimum, maximum,
    userData,
  ]), 1); // APPLICATION[1]

  return x224Data(ci);
}

/** Parse MCS Connect-Response to extract channel IDs from user data */
export function parseMcsConnectResponse(payload: Buffer): {
  ioChannelId: number;
  channelIds:  number[];
} {
  // The standard I/O channel is always 1003
  // Parse GCC user data to find channel list from server
  // For simplicity, use the well-known defaults
  return { ioChannelId: 1003, channelIds: [1003] };
}

// ── MCS PDUs (post-connect) ───────────────────────────────────────────────

export function mcsErectDomain(): Buffer {
  return x224Data(Buffer.from([0x04, 0x01, 0x00, 0x01, 0x00]));
}

export function mcsAttachUser(): Buffer {
  return x224Data(Buffer.from([0x28]));
}

export function parseMcsAttachUserConfirm(payload: Buffer): number {
  // [0x2c][result][initiator hi][initiator lo]
  if (payload[0] !== 0x2c) return 0;
  return ((payload[2] << 8) | payload[3]) + 1001;
}

export function mcsChannelJoin(userId: number, channelId: number): Buffer {
  const buf = Buffer.alloc(5);
  buf[0] = 0x38;
  buf.writeUInt16BE(userId    - 1001, 1);
  buf.writeUInt16BE(channelId - 1001, 3);
  return x224Data(buf);
}

export function parseMcsChannelJoinConfirm(payload: Buffer): number {
  // [0x3e][result][initiator][channelId]
  if (payload[0] !== 0x3e) return 0;
  return ((payload[4] << 8) | payload[5]) + 1001;
}

// ── MCS SendDataRequest (wraps RDP PDUs) ─────────────────────────────────

export function mcsSend(userId: number, channelId: number, data: Buffer): Buffer {
  const hdr = Buffer.alloc(8);
  hdr[0] = 0x64; // SendDataRequest
  hdr.writeUInt16BE(userId    - 1001, 1);
  hdr.writeUInt16BE(channelId - 1001, 3);
  hdr[5] = 0x70; // priority + segmentation = complete
  hdr.writeUInt16BE(data.length, 6);
  return x224Data(Buffer.concat([hdr, data]));
}

/** Parse MCS SendDataIndication → returns {channelId, payload} */
export function parseMcsSend(raw: Buffer): { channelId: number; payload: Buffer } | null {
  const p = stripX224(raw);
  if (p[0] !== 0x68 && p[0] !== 0x08) return null; // SendDataIndication
  // Parse: skip [0x68][userId 2b][channelId 2b][flags 1b][len 2b]
  const channelId = p.readUInt16BE(3) + 1001;
  const len       = p.readUInt16BE(6);
  return { channelId, payload: p.slice(8, 8 + len) };
}

// ── RDP Security (NLA path — no encryption needed) ────────────────────────

/** Security header (NLA path: no encryption, just sequence number) */
export function secHdr(flags = 0): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(flags);
  return b;
}

// ── Share Control Header ──────────────────────────────────────────────────

export const PDU_TYPE_DEMAND_ACTIVE  = 0x1001;
export const PDU_TYPE_CONFIRM_ACTIVE = 0x0013;
export const PDU_TYPE_DATA           = 0x0007;

export function shareCtrlHdr(pduType: number, userId: number, payload: Buffer): Buffer {
  const hdr = Buffer.alloc(6);
  hdr.writeUInt16LE(payload.length + 6, 0); // totalLength
  hdr.writeUInt16LE(pduType, 2);
  hdr.writeUInt16LE(userId, 4);
  return Buffer.concat([hdr, payload]);
}

export function parseShareCtrl(payload: Buffer): { pduType: number; pduSource: number; body: Buffer } {
  const totalLen = payload.readUInt16LE(0);
  const pduType  = payload.readUInt16LE(2) & 0x0f; // low 4 bits = PDU type ID
  const pduType2 = payload.readUInt16LE(2);
  const pduSource = payload.readUInt16LE(4);
  return { pduType: pduType2, pduSource, body: payload.slice(6, totalLen) };
}

// ── Share Data Header ─────────────────────────────────────────────────────

export const PDUTYPE2_UPDATE          = 0x02;
export const PDUTYPE2_SYNCHRONIZE     = 0x1F;
export const PDUTYPE2_CONTROL         = 0x14;
export const PDUTYPE2_FONTLIST        = 0x27;
export const PDUTYPE2_FONTMAP         = 0x28;
export const PDUTYPE2_SET_KEYBOARD    = 0x2C;

export function shareDataHdr(shareId: number, type2: number, payload: Buffer): Buffer {
  const hdr = Buffer.alloc(18);
  hdr.writeUInt32LE(shareId, 0);
  hdr[4] = 0;    // pad
  hdr[5] = 1;    // streamId = STREAM_MED
  hdr.writeUInt16LE(payload.length + 18, 6);  // uncompressedLength
  hdr[8]  = type2;
  hdr[9]  = 0;   // compressedType
  hdr.writeUInt16LE(0, 10);
  return Buffer.concat([hdr, payload]);
}

export function parseShareData(body: Buffer): { type2: number; data: Buffer } {
  const type2 = body[8];
  return { type2, data: body.slice(18) };
}

// ── Client Info PDU ───────────────────────────────────────────────────────

export function buildClientInfo(username: string, password: string, domain: string): Buffer {
  const INFO_AUTOLOGON         = 0x00000008;
  const INFO_UNICODE           = 0x00000010;
  const INFO_ENABLEWINDOWSKEY  = 0x00000100;
  const INFO_DISABLECTRLALTDEL = 0x00000002;
  const INFO_NOAUDIOPLAYBACK   = 0x00080000;
  const INFO_HIDEF_RAIL_SUPPORTED = 0x02000000;
  const flags = INFO_AUTOLOGON | INFO_UNICODE | INFO_ENABLEWINDOWSKEY;

  const dom  = Buffer.from(domain,   'utf16le');
  const usr  = Buffer.from(username, 'utf16le');
  const pwd  = Buffer.from(password, 'utf16le');
  const sh   = Buffer.alloc(2); // empty alternateShell
  const wd   = Buffer.alloc(2); // empty workingDir

  const fixed = Buffer.alloc(18);
  fixed.writeUInt32LE(0x0409, 0);          // codePage (EN-US)
  fixed.writeUInt32LE(flags, 4);
  fixed.writeUInt16LE(dom.length, 8);
  fixed.writeUInt16LE(usr.length, 10);
  fixed.writeUInt16LE(pwd.length, 12);
  fixed.writeUInt16LE(0, 14);  // cbAlternateShell = 0 (empty)
  fixed.writeUInt16LE(0, 16);  // cbWorkingDir = 0 (empty)

  const infoBody = Buffer.concat([fixed, dom, Buffer.alloc(2), usr, Buffer.alloc(2), pwd, Buffer.alloc(2), sh, wd]);

  // Extended Info (TS_EXTENDED_INFO_PACKET)
  // clientAddress and clientDir are empty UTF-16LE strings (2-byte null each)
  const clientAddr = Buffer.alloc(2, 0); // UTF-16LE null
  const clientDir  = Buffer.alloc(2, 0); // UTF-16LE null
  const timeZone   = Buffer.alloc(172, 0); // TS_TIME_ZONE_INFORMATION (all zeros = UTC)
  // Total: 2+2+2+2+2+172+4+4+2 = 192 bytes
  const ext = Buffer.alloc(192, 0);
  let off = 0;
  ext.writeUInt16LE(0x0002, off); off += 2; // clientAddressFamily = AF_INET
  ext.writeUInt16LE(clientAddr.length, off); off += 2; // cbClientAddress
  clientAddr.copy(ext, off); off += clientAddr.length;
  ext.writeUInt16LE(clientDir.length, off); off += 2; // cbClientDir
  clientDir.copy(ext, off); off += clientDir.length;
  timeZone.copy(ext, off); off += 172;                // clientTimeZone
  ext.writeUInt32LE(0, off); off += 4;                // clientSessionId
  ext.writeUInt32LE(0, off); off += 4;                // performanceFlags
  ext.writeUInt16LE(0, off);                          // cbAutoReconnectCookie

  return Buffer.concat([infoBody, ext]);
}

// ── Capability sets ───────────────────────────────────────────────────────

function capHdr(type: number, data: Buffer): Buffer {
  const h = Buffer.alloc(4);
  h.writeUInt16LE(type, 0);
  h.writeUInt16LE(data.length + 4, 2);
  return Buffer.concat([h, data]);
}

export function buildCapabilities(width: number, height: number): Buffer {
  // GENERAL
  const general = Buffer.alloc(20);
  general.writeUInt16LE(1, 0);   // osMajorType = Windows
  general.writeUInt16LE(3, 2);   // osMinorType = Windows NT
  general.writeUInt16LE(0x0200, 4); // protocolVersion
  general.writeUInt16LE(0, 6);   // pad
  general.writeUInt16LE(0, 8);   // compressionTypes
  general.writeUInt16LE(0x0400, 10); // extraFlags (FASTPATH_OUTPUT_SUPPORTED)
  general.writeUInt16LE(0, 12); general.writeUInt16LE(0, 14); general.writeUInt16LE(0, 16);
  general[18] = 0; general[19] = 1; // suppressOutput

  // BITMAP
  const bitmap = Buffer.alloc(24);
  bitmap.writeUInt16LE(32, 0);   // preferredBitsPerPixel
  bitmap.writeUInt16LE(1, 2);    // receive1Bit
  bitmap.writeUInt16LE(1, 4);    // receive4Bit
  bitmap.writeUInt16LE(1, 6);    // receive8Bit
  bitmap.writeUInt16LE(width, 8);
  bitmap.writeUInt16LE(height, 10);
  bitmap.writeUInt16LE(0, 12);   // pad
  bitmap.writeUInt16LE(1, 14);   // desktopResizeFlag
  bitmap.writeUInt16LE(1, 16);   // bitmapCompressionFlag
  bitmap[18] = 0;                 // highColorFlags
  bitmap[19] = 0x1e;              // drawingFlags
  bitmap.writeUInt16LE(1, 20);   // multipleRectangleSupport
  bitmap.writeUInt16LE(0, 22);

  // ORDER (minimal — no drawing orders, forces bitmap updates)
  const order = Buffer.alloc(84);
  order.writeUInt16LE(1, 16);   // desktopSaveXGranularity
  order.writeUInt16LE(20, 18);  // desktopSaveYGranularity
  order.writeUInt16LE(1, 22);   // maximumOrderLevel
  order.writeUInt16LE(0x0002, 26); // orderFlags: ZEROBOUNDSDELTASSUPPORT only
  // orderSupport: 32 bytes zeros (no orders)
  order.writeUInt32LE(0x000F4240, 68); // desktopSaveSize

  // POINTER
  const pointer = Buffer.alloc(6);
  pointer.writeUInt16LE(1, 0);   // colorPointerFlag
  pointer.writeUInt16LE(25, 2);  // colorPointerCacheSize
  pointer.writeUInt16LE(25, 4);  // pointerCacheSize

  // INPUT
  const input = Buffer.alloc(84);
  input.writeUInt16LE(0x0037, 0); // INPUT_FLAG_SCANCODES|FASTPATH_INPUT2|UNICODE|MOUSEX
  input.writeUInt32LE(0x0409, 4);
  input.writeUInt32LE(4, 8);      // keyboardType
  input.writeUInt32LE(0, 12);
  input.writeUInt32LE(12, 16);    // keyboardFunctionKey

  // VIRTUALCHANNEL
  const vc = Buffer.alloc(8);
  vc.writeUInt32LE(1, 0); // VCCAPS_COMPR_CS_8K
  vc.writeUInt32LE(0, 4);

  // MULTIFRAGMENTUPDATE
  const mfu = Buffer.alloc(4);
  mfu.writeUInt32LE(64 * 1024 * 1024, 0); // 64MB max fragment

  return Buffer.concat([
    capHdr(0x0001, general),
    capHdr(0x0002, bitmap),
    capHdr(0x0003, order),
    capHdr(0x0008, pointer),
    capHdr(0x000D, input),
    capHdr(0x0014, vc),
    capHdr(0x0021, mfu),
  ]);
}

// ── Confirm Active PDU ────────────────────────────────────────────────────

export function buildConfirmActive(shareId: number, userId: number, ioChannelId: number, caps: Buffer): Buffer {
  const src = Buffer.from('MS RDP', 'ascii');
  const body = Buffer.alloc(4 + 2 + src.length + 2 + 2 + caps.length);
  body.writeUInt32LE(shareId, 0);
  body.writeUInt16LE(src.length + 2, 4); // lengthSourceDescriptor
  src.copy(body, 6);
  body.writeUInt8(0, 6 + src.length); body.writeUInt8(0, 7 + src.length); // null terminator
  const numCaps = 7; // must match buildCapabilities()
  body.writeUInt16LE(numCaps, 8 + src.length);
  body.writeUInt16LE(0, 10 + src.length); // pad
  caps.copy(body, 12 + src.length);

  const sctrl = shareCtrlHdr(PDU_TYPE_CONFIRM_ACTIVE, userId, body);
  return mcsSend(userId, ioChannelId, Buffer.concat([secHdr(), sctrl]));
}

// ── Synchronize / Control / FontList (finalization) ───────────────────────

export function buildSynchronize(shareId: number, userId: number, ioChannelId: number): Buffer {
  const data = Buffer.alloc(4);
  data.writeUInt16LE(1, 0); // messageType = SYNCMSGTYPE_SYNC
  data.writeUInt16LE(1002, 2); // targetUser
  const body = shareDataHdr(shareId, PDUTYPE2_SYNCHRONIZE, data);
  const sctrl = shareCtrlHdr(PDU_TYPE_DATA, userId, body);
  return mcsSend(userId, ioChannelId, Buffer.concat([secHdr(), sctrl]));
}

export function buildControl(shareId: number, userId: number, ioChannelId: number, action: number): Buffer {
  const data = Buffer.alloc(8);
  data.writeUInt16LE(action, 0);
  data.writeUInt16LE(0, 2);
  data.writeUInt32LE(0, 4);
  const body = shareDataHdr(shareId, PDUTYPE2_CONTROL, data);
  const sctrl = shareCtrlHdr(PDU_TYPE_DATA, userId, body);
  return mcsSend(userId, ioChannelId, Buffer.concat([secHdr(), sctrl]));
}

export function buildFontList(shareId: number, userId: number, ioChannelId: number): Buffer {
  const data = Buffer.alloc(8);
  data.writeUInt16LE(0, 0); data.writeUInt16LE(0, 2);
  data.writeUInt16LE(3, 4); data.writeUInt16LE(50, 6);
  const body = shareDataHdr(shareId, PDUTYPE2_FONTLIST, data);
  const sctrl = shareCtrlHdr(PDU_TYPE_DATA, userId, body);
  return mcsSend(userId, ioChannelId, Buffer.concat([secHdr(), sctrl]));
}

// ── Fast-Path Input Events ────────────────────────────────────────────────

const FASTPATH_INPUT_EVENT_MOUSE   = 0x01;
const FASTPATH_INPUT_EVENT_MOUSEX  = 0x02;
const FASTPATH_INPUT_EVENT_UNICODE = 0x03;
const FASTPATH_INPUT_EVENT_SCANCODE = 0x00;

export function buildFpMouse(x: number, y: number, pointerFlags: number): Buffer {
  const event = Buffer.alloc(7);
  event[0] = FASTPATH_INPUT_EVENT_MOUSE;
  event.writeUInt16LE(pointerFlags, 1);
  event.writeUInt16LE(x, 3);
  event.writeUInt16LE(y, 5);
  return wrapFpInput([event]);
}

export function buildFpKeyboard(scancode: number, flags: number): Buffer {
  const event = Buffer.alloc(2);
  event[0] = FASTPATH_INPUT_EVENT_SCANCODE | (flags << 5);
  event[1] = scancode;
  return wrapFpInput([event]);
}

function wrapFpInput(events: Buffer[]): Buffer {
  const payload = Buffer.concat(events);
  // Fast-path header: action=FASTPATH (0x00) | numEvents in bits 2-5
  const numEvents = events.length;
  const fpHdr = Buffer.alloc(3);
  fpHdr[0] = (numEvents << 2) & 0xff; // action=0 | numEvents
  // 2-byte length (high bit set)
  const len = 3 + payload.length;
  fpHdr[1] = 0x80 | (len >> 8);
  fpHdr[2] = len & 0xff;
  return Buffer.concat([fpHdr, payload]);
}

// Mouse pointer flags (TS_POINTER_EVENT)
export const PTR_FLAGS_BUTTON1 = 0x1000;
export const PTR_FLAGS_BUTTON2 = 0x2000;
export const PTR_FLAGS_BUTTON3 = 0x4000;
export const PTR_FLAGS_WHEEL   = 0x0200;
export const PTR_FLAGS_HWHEEL  = 0x0400;
export const PTR_FLAGS_DOWN    = 0x8000;
export const PTR_FLAGS_MOVE    = 0x0800;
