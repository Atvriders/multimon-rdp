/**
 * RDP Client — full protocol state machine.
 * Connects directly to Windows :3389 via TCP+TLS (NLA).
 * Emits 'bitmap' events with raw RGBA tile data.
 */
import * as net  from 'net';
import * as tls  from 'tls';
import { EventEmitter } from 'events';

import { buildNegotiate, parseChallenge, buildAuthenticate } from './ntlm';
import { buildTsRequestToken, buildTsRequestAuth, parseTsRequest } from './credssp';
import {
  x224ConnectReq, parseX224CC, PROTO_HYBRID,
  mcsConnectInitial, parseMcsConnectResponse,
  mcsErectDomain, mcsAttachUser, parseMcsAttachUserConfirm,
  mcsChannelJoin, parseMcsChannelJoinConfirm,
  mcsSend, parseMcsSend, stripX224,
  secHdr, shareCtrlHdr, parseShareCtrl, parseShareData,
  PDU_TYPE_DEMAND_ACTIVE, PDU_TYPE_CONFIRM_ACTIVE, PDU_TYPE_DATA,
  PDUTYPE2_UPDATE, PDUTYPE2_SYNCHRONIZE, PDUTYPE2_CONTROL, PDUTYPE2_FONTMAP,
  buildClientInfo, buildCapabilities, buildConfirmActive,
  buildSynchronize, buildControl, buildFontList,
  buildFpMouse, buildFpKeyboard,
  PTR_FLAGS_MOVE, PTR_FLAGS_DOWN, PTR_FLAGS_BUTTON1, PTR_FLAGS_BUTTON2,
  PTR_FLAGS_BUTTON3, PTR_FLAGS_WHEEL,
  parseTpktLen,
} from './pdu';
import { parseFpBitmap, BitmapTile } from './bitmap';

// ── Types ─────────────────────────────────────────────────────────────────

export interface RdpConfig {
  host:         string;
  port:         number;
  username:     string;
  password:     string;
  domain:       string;
  monitorWidth: number;
  monitorHeight: number;
  monitorCount: number;
  ignoreCert:   boolean;
}

const enum Phase {
  TCP_CONNECT, X224, NLA_NEGOTIATE, NLA_AUTHENTICATE, MCS_CONNECT,
  MCS_ERECT, MCS_ATTACH, CHANNEL_JOIN, CLIENT_INFO, CAPABILITIES,
  SYNC_FINALIZE, ACTIVE, CLOSED,
}

export class RdpClient extends EventEmitter {
  private socket: tls.TLSSocket | null = null;
  private recvBuf = Buffer.alloc(0);
  private phase   = Phase.TCP_CONNECT;

  private userId      = 0;
  private ioChannelId = 1003;
  private shareId     = 0;
  private channelsToJoin: number[] = [];
  private channelsJoined = 0;

  private negotiateMsg  = Buffer.alloc(0);
  private challengeMsg  = Buffer.alloc(0);

  constructor(private cfg: RdpConfig) { super(); }

  // ── Public API ──────────────────────────────────────────────────────────

  connect(): void {
    const raw = net.createConnection(this.cfg.port, this.cfg.host);
    raw.once('connect', () => {
      this.phase = Phase.X224;
      raw.write(x224ConnectReq(PROTO_HYBRID));
    });
    raw.once('error', (e) => this.emit('error', e));
    raw.once('close', () => this.close());
    raw.on('data', (chunk: Buffer) => this.onRawData(chunk));
  }

  sendMouse(x: number, y: number, buttons: number, wheelDelta = 0): void {
    if (this.phase !== Phase.ACTIVE || !this.socket) return;
    let flags = PTR_FLAGS_MOVE;
    if (buttons & 1) flags |= PTR_FLAGS_BUTTON1 | PTR_FLAGS_DOWN;
    if (buttons & 2) flags |= PTR_FLAGS_BUTTON3 | PTR_FLAGS_DOWN;
    if (buttons & 4) flags |= PTR_FLAGS_BUTTON2 | PTR_FLAGS_DOWN;
    if (wheelDelta !== 0) {
      flags = PTR_FLAGS_WHEEL | (wheelDelta < 0 ? 0x0100 : 0) | (Math.abs(wheelDelta) & 0xff);
    }
    this.socket.write(buildFpMouse(x, y, flags));
  }

  sendKey(scancode: number, down: boolean): void {
    if (this.phase !== Phase.ACTIVE || !this.socket) return;
    this.socket.write(buildFpKeyboard(scancode, down ? 0 : 1));
  }

  disconnect(): void {
    this.phase = Phase.CLOSED;
    this.socket?.destroy();
    this.emit('close');
  }

  // ── Receive buffer management ───────────────────────────────────────────

  private onRawData(chunk: Buffer): void {
    this.recvBuf = Buffer.concat([this.recvBuf, chunk]);
    this.drain();
  }

  private drain(): void {
    while (true) {
      if (this.phase === Phase.NLA_NEGOTIATE || this.phase === Phase.NLA_AUTHENTICATE) {
        // CredSSP: length-prefixed TLS record, no TPKT
        if (this.recvBuf.length < 4) return;
        // ASN.1 DER: [0x30][len...]
        if (this.recvBuf[0] !== 0x30) { this.onError('Expected ASN.1'); return; }
        const { len, consumed } = derLen(this.recvBuf, 1);
        const total = 1 + consumed + len;
        if (this.recvBuf.length < total) return;
        const frame = this.recvBuf.slice(0, total);
        this.recvBuf = this.recvBuf.slice(total);
        this.handleNla(frame);
      } else {
        // All other phases: TPKT framing
        if (this.recvBuf.length < 4) return;
        const tpktLen = parseTpktLen(this.recvBuf);
        if (tpktLen <= 0 || this.recvBuf.length < tpktLen) return;
        const frame = this.recvBuf.slice(0, tpktLen);
        this.recvBuf = this.recvBuf.slice(tpktLen);
        this.handleTpkt(frame);
      }
    }
  }

  // ── X.224 / NLA handshake ───────────────────────────────────────────────

  private handleTpkt(frame: Buffer): void {
    switch (this.phase) {
      case Phase.X224:       this.onX224Confirm(frame); break;
      case Phase.MCS_CONNECT: this.onMcsResponse(frame); break;
      case Phase.MCS_ERECT:  // fall through — no response expected
      case Phase.MCS_ATTACH: this.onMcsAttach(frame); break;
      case Phase.CHANNEL_JOIN: this.onChannelJoin(frame); break;
      case Phase.CLIENT_INFO:  this.onClientInfo(frame); break;
      case Phase.CAPABILITIES: this.onCapabilities(frame); break;
      case Phase.SYNC_FINALIZE: this.onSyncFinalize(frame); break;
      case Phase.ACTIVE:       this.onActiveData(frame); break;
    }
  }

  private onX224Confirm(frame: Buffer): void {
    const proto = parseX224CC(frame);
    if (proto !== PROTO_HYBRID) {
      this.onError(`Server selected protocol ${proto}, expected NLA`);
      return;
    }
    // Upgrade to TLS
    const raw = (this.socket as unknown as net.Socket) ?? undefined;
    const rawSocket = (this as unknown as { _rawSocket?: net.Socket })._rawSocket;
    // We need the raw socket — it's stored internally; upgrade via tls.connect
    this.upgradeTls(frame);
  }

  private upgradeTls(x224Frame: Buffer): void {
    // The raw TCP socket that was reading X.224 data
    const listeners = this.rawListeners('_socket') as unknown[];
    // Hack: we use a stored reference from connect()
    const tcp = this._tcp!;
    tcp.removeAllListeners('data');

    const tlsSock = new tls.TLSSocket(tcp, {
      rejectUnauthorized: !this.cfg.ignoreCert,
      requestCert: false,
    });
    this.socket = tlsSock;

    tlsSock.once('secureConnect', () => {
      this.phase = Phase.NLA_NEGOTIATE;
      // Send NTLM Negotiate wrapped in TSRequest
      this.negotiateMsg = buildNegotiate();
      const tsReq = buildTsRequestToken(this.negotiateMsg);
      tlsSock.write(tsReq);
    });
    tlsSock.on('data', (chunk: Buffer) => this.onRawData(chunk));
    tlsSock.once('error', (e) => this.emit('error', e));
    tlsSock.once('close', () => this.close());
  }

  private _tcp: net.Socket | null = null;

  // Override connect to store raw TCP ref
  connect(): void {
    const raw = net.createConnection(this.cfg.port, this.cfg.host);
    this._tcp = raw;
    raw.once('connect', () => {
      this.phase = Phase.X224;
      raw.write(x224ConnectReq(PROTO_HYBRID));
    });
    raw.once('error', (e) => this.emit('error', e));
    raw.once('close', () => this.close());
    raw.on('data', (chunk: Buffer) => this.onRawData(chunk));
  }

  private handleNla(frame: Buffer): void {
    const resp = parseTsRequest(frame);

    if (this.phase === Phase.NLA_NEGOTIATE) {
      if (!resp.negoToken) { this.onError('No NTLM challenge token'); return; }
      this.challengeMsg = resp.negoToken;
      const ch = parseChallenge(this.challengeMsg);
      const { msg: authMsg, exportedSession } = buildAuthenticate(
        this.cfg.username, this.cfg.password, this.cfg.domain,
        ch, this.negotiateMsg, this.challengeMsg,
      );
      // pubKeyAuth
      const { computePubKeyAuth } = require('./credssp') as typeof import('./credssp');
      const pubKeyAuth = computePubKeyAuth(this.socket!, exportedSession);
      const tsReq = buildTsRequestAuth(authMsg, pubKeyAuth);
      this.phase = Phase.NLA_AUTHENTICATE;
      this.socket!.write(tsReq);
    } else if (this.phase === Phase.NLA_AUTHENTICATE) {
      // NLA complete — send MCS Connect-Initial
      this.phase = Phase.MCS_CONNECT;
      const mci = mcsConnectInitial(
        this.cfg.monitorWidth, this.cfg.monitorHeight,
        this.cfg.monitorCount, this.cfg.monitorWidth, this.cfg.monitorHeight,
      );
      this.socket!.write(mci);
    }
  }

  // ── MCS connection ──────────────────────────────────────────────────────

  private onMcsResponse(frame: Buffer): void {
    const { ioChannelId } = parseMcsConnectResponse(stripX224(frame));
    this.ioChannelId = ioChannelId;
    this.phase = Phase.MCS_ERECT;
    this.socket!.write(mcsErectDomain());
    this.phase = Phase.MCS_ATTACH;
    this.socket!.write(mcsAttachUser());
  }

  private onMcsAttach(frame: Buffer): void {
    const p = stripX224(frame);
    this.userId = parseMcsAttachUserConfirm(p);
    if (!this.userId) return;
    this.phase = Phase.CHANNEL_JOIN;
    this.channelsToJoin = [this.userId, this.ioChannelId];
    this.channelsJoined = 0;
    this.socket!.write(mcsChannelJoin(this.userId, this.channelsToJoin[0]));
  }

  private onChannelJoin(frame: Buffer): void {
    this.channelsJoined++;
    if (this.channelsJoined < this.channelsToJoin.length) {
      this.socket!.write(mcsChannelJoin(this.userId, this.channelsToJoin[this.channelsJoined]));
    } else {
      // All channels joined — send Client Info
      this.phase = Phase.CLIENT_INFO;
      const info = buildClientInfo(this.cfg.username, this.cfg.password, this.cfg.domain);
      const sctrl = shareCtrlHdr(PDU_TYPE_DATA, this.userId,
        Buffer.concat([Buffer.alloc(18), info]));  // shareDataHdr placeholder
      // Actually send as a proper data PDU using pdu helpers
      const infoRaw = Buffer.concat([secHdr(), info]);
      // Client Info uses security header + TS_INFO_PACKET (no shareControl)
      const clientInfoPdu = Buffer.concat([secHdr(0x0040), info]); // SEC_INFO_PKT
      this.socket!.write(wrapInMcs(this.userId, this.ioChannelId, clientInfoPdu));
    }
  }

  private onClientInfo(frame: Buffer): void {
    // Waiting for server capability data (Demand Active)
    this.phase = Phase.CAPABILITIES;
    this.onCapabilities(frame);
  }

  private onCapabilities(frame: Buffer): void {
    // Could be licensing PDUs or Demand Active
    const mcs = parseMcsSend(frame);
    if (!mcs) return;
    const { pduType, body } = parseShareCtrl(mcs.payload.slice(4)); // skip sec hdr
    if (pduType !== PDU_TYPE_DEMAND_ACTIVE) return; // licensing — ignore

    this.shareId = body.readUInt32LE(0);
    const totalW = this.cfg.monitorWidth * this.cfg.monitorCount;
    const caps   = buildCapabilities(totalW, this.cfg.monitorHeight);
    this.socket!.write(buildConfirmActive(this.shareId, this.userId, this.ioChannelId, caps));

    this.phase = Phase.SYNC_FINALIZE;
    this.socket!.write(buildSynchronize(this.shareId, this.userId, this.ioChannelId));
    this.socket!.write(buildControl(this.shareId, this.userId, this.ioChannelId, 4)); // cooperate
    this.socket!.write(buildControl(this.shareId, this.userId, this.ioChannelId, 1)); // request control
    this.socket!.write(buildFontList(this.shareId, this.userId, this.ioChannelId));
  }

  private onSyncFinalize(frame: Buffer): void {
    const mcs = parseMcsSend(frame);
    if (!mcs) return;
    try {
      const { pduType, body } = parseShareCtrl(mcs.payload.slice(4));
      if (pduType === PDU_TYPE_DATA) {
        const { type2 } = parseShareData(body);
        if (type2 === PDUTYPE2_FONTMAP) {
          // Ready — enter active state
          this.phase = Phase.ACTIVE;
          this.emit('ready');
        }
      }
    } catch { /* ignore parsing errors during finalization */ }
  }

  // ── Active data: bitmap updates ─────────────────────────────────────────

  private onActiveData(frame: Buffer): void {
    // Could be Fast-Path or Slow-Path
    if (frame[0] !== 3) {
      // Fast-Path (action bits 0-1 = 00)
      this.handleFastPath(frame);
    } else {
      this.handleSlowPath(frame);
    }
  }

  private handleFastPath(frame: Buffer): void {
    // TS_FP_UPDATE_PDU
    let off = 1;
    // Length: 1 or 2 bytes
    const b1 = frame[off++];
    const fpLen = (b1 & 0x80) ? (((b1 & 0x7f) << 8) | frame[off++]) : b1;

    // Parse updates
    while (off < frame.length) {
      const updateCode  = frame[off++];
      const updateType  = updateCode & 0x0f;
      const fragFlags   = (updateCode >> 4) & 0x03;
      const compression = (updateCode >> 6) & 0x03;

      // Length of this update
      if (off + 2 > frame.length) break;
      const updateLen = frame.readUInt16LE(off); off += 2;
      if (off + updateLen > frame.length) break;
      const updateData = frame.slice(off, off + updateLen); off += updateLen;

      if (updateType === 0x01) { // FASTPATH_UPDATETYPE_BITMAP
        const tiles = parseFpBitmap(updateData);
        tiles.forEach(t => this.emit('bitmap', t));
      }
      // Skip other update types (pointer, palette, etc.)
    }
  }

  private handleSlowPath(frame: Buffer): void {
    const mcs = parseMcsSend(frame);
    if (!mcs) return;
    try {
      const { pduType, body } = parseShareCtrl(mcs.payload.slice(4));
      if (pduType === PDU_TYPE_DATA) {
        const { type2, data } = parseShareData(body);
        if (type2 === PDUTYPE2_UPDATE) {
          const updateType = data.readUInt16LE(0);
          if (updateType === 0x0001) { // UPDATETYPE_BITMAP
            const tiles = parseFpBitmap(data.slice(2));
            tiles.forEach(t => this.emit('bitmap', t));
          }
        }
      }
    } catch { /* ignore */ }
  }

  // ── Error / close ───────────────────────────────────────────────────────

  private onError(msg: string): void {
    this.emit('error', new Error(`RDP[${this.cfg.host}]: ${msg}`));
    this.close();
  }

  private close(): void {
    if (this.phase === Phase.CLOSED) return;
    this.phase = Phase.CLOSED;
    this.socket?.destroy();
    this.emit('close');
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────

function derLen(buf: Buffer, i: number): { len: number; consumed: number } {
  const b = buf[i];
  if (b < 0x80) return { len: b, consumed: 1 };
  const n = b & 0x7f;
  let len = 0;
  for (let k = 0; k < n; k++) len = (len << 8) | buf[i + 1 + k];
  return { len, consumed: 1 + n };
}

function wrapInMcs(userId: number, channelId: number, data: Buffer): Buffer {
  return mcsSend(userId, channelId, data);
}
