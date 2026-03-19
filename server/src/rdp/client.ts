/**
 * RDP Client — full protocol state machine.
 * Connects directly to Windows :3389 via TCP+TLS (NLA/CredSSP).
 * Emits 'bitmap' events with raw RGBA tile data.
 */
import * as net  from 'net';
import * as tls  from 'tls';
import { EventEmitter } from 'events';

import { buildNegotiate, parseChallenge, buildAuthenticate } from './ntlm';
import {
  buildTsRequestToken, buildTsRequestAuth, buildTsRequestAuthInfo,
  parseTsRequest, computePubKeyAuth, SealingContext,
} from './credssp';
import {
  x224ConnectReq, parseX224CC, PROTO_HYBRID,
  mcsConnectInitial, parseMcsConnectResponse,
  mcsErectDomain, mcsAttachUser, parseMcsAttachUserConfirm,
  mcsChannelJoin,
  mcsSend, parseMcsSend, stripX224,
  secHdr, shareCtrlHdr, parseShareCtrl, parseShareData,
  PDU_TYPE_DEMAND_ACTIVE, PDU_TYPE_DATA,
  PDUTYPE2_UPDATE, PDUTYPE2_FONTMAP,
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
  host:          string;
  port:          number;
  username:      string;
  password:      string;
  domain:        string;
  monitorWidth:  number;
  monitorHeight: number;
  monitorCount:  number;
  ignoreCert:    boolean;
}

const enum Phase {
  TCP_CONNECT, X224, NLA_NEGOTIATE, NLA_AUTHENTICATE, NLA_CREDENTIALS, MCS_CONNECT,
  MCS_ERECT, MCS_ATTACH, CHANNEL_JOIN, CLIENT_INFO, CAPABILITIES,
  SYNC_FINALIZE, ACTIVE, CLOSED,
}

export class RdpClient extends EventEmitter {
  private tcp:    net.Socket    | null = null;
  private socket: tls.TLSSocket | null = null;
  private recvBuf: Buffer = Buffer.alloc(0);
  private phase = Phase.TCP_CONNECT;

  private userId        = 0;
  private ioChannelId   = 1003;
  private shareId       = 0;
  private channelsToJoin: number[] = [];
  private channelsJoined = 0;

  private negotiateMsg:   Uint8Array    = Buffer.alloc(0);
  private challengeMsg:   Uint8Array    = Buffer.alloc(0);
  private sealingCtx:     SealingContext | null = null;

  constructor(private cfg: RdpConfig) { super(); }

  // ── Public API ──────────────────────────────────────────────────────────

  connect(): void {
    const raw = net.createConnection(this.cfg.port, this.cfg.host);
    this.tcp = raw;
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
    this.tcp?.destroy();
    this.emit('close');
  }

  // ── Receive buffer ──────────────────────────────────────────────────────

  private onRawData(chunk: Buffer): void {
    this.recvBuf = Buffer.concat([this.recvBuf, chunk]);
    if (this.phase >= Phase.MCS_CONNECT && this.phase <= Phase.SYNC_FINALIZE) {
      console.log(`[rdp ${this.cfg.host}] data phase=${this.phase} bytes=${chunk.length} first=${chunk.slice(0,4).toString('hex')}`);
    }
    this.drain();
  }

  private drain(): void {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (this.phase === Phase.NLA_NEGOTIATE || this.phase === Phase.NLA_AUTHENTICATE || this.phase === Phase.NLA_CREDENTIALS) {
        if (this.recvBuf.length < 2) return;
        if (this.recvBuf[0] !== 0x30) { this.onError('Expected ASN.1 SEQUENCE'); return; }
        const { len, consumed } = readDerLen(this.recvBuf, 1);
        const total = 1 + consumed + len;
        if (this.recvBuf.length < total) return;
        const frame = Buffer.from(this.recvBuf.slice(0, total));
        this.recvBuf = Buffer.from(this.recvBuf.slice(total));
        this.handleNla(frame);
      } else {
        if (this.recvBuf.length < 4) return;
        const tpktLen = parseTpktLen(this.recvBuf);
        if (tpktLen === -1) {
          // Not a TPKT — may be a residual TSRequest the server sent after authInfo.
          // Skip the ASN.1 SEQUENCE frame and keep going.
          if (this.recvBuf[0] === 0x30) {
            if (this.recvBuf.length < 2) return;
            const { len, consumed } = readDerLen(this.recvBuf, 1);
            const total = 1 + consumed + len;
            if (this.recvBuf.length < total) return;
            console.log(`[rdp ${this.cfg.host}] Skipping ${total}-byte residual TSRequest in phase ${this.phase}`);
            this.recvBuf = Buffer.from(this.recvBuf.slice(total));
            continue;
          }
          this.onError(`Unexpected byte 0x${this.recvBuf[0].toString(16)} in RDP stream (phase ${this.phase})`);
          return;
        }
        if (tpktLen === 0 || this.recvBuf.length < tpktLen) return;
        const frame = Buffer.from(this.recvBuf.slice(0, tpktLen));
        this.recvBuf = Buffer.from(this.recvBuf.slice(tpktLen));
        this.handleTpkt(frame);
      }
    }
  }

  // ── X.224 / TLS upgrade ─────────────────────────────────────────────────

  private handleTpkt(frame: Buffer): void {
    switch (this.phase) {
      case Phase.X224:          this.onX224Confirm(frame);   break;
      case Phase.MCS_CONNECT:   this.onMcsResponse(frame);   break;
      case Phase.MCS_ERECT:
      case Phase.MCS_ATTACH:    this.onMcsAttach(frame);     break;
      case Phase.CHANNEL_JOIN:  this.onChannelJoin(frame);   break;
      case Phase.CLIENT_INFO:
      case Phase.CAPABILITIES:  this.onCapabilities(frame);  break;
      case Phase.SYNC_FINALIZE: this.onSyncFinalize(frame);  break;
      case Phase.ACTIVE:        this.onActiveData(frame);    break;
    }
  }

  private onX224Confirm(frame: Buffer): void {
    const proto = parseX224CC(frame);
    if (proto !== PROTO_HYBRID) {
      this.onError(`Server requires protocol ${proto}, need NLA (${PROTO_HYBRID})`);
      return;
    }
    this.upgradeTls();
  }

  private upgradeTls(): void {
    const tcp = this.tcp!;
    tcp.removeAllListeners('data');

    const tlsSock = new tls.TLSSocket(tcp, {
      rejectUnauthorized: !this.cfg.ignoreCert,
    });
    this.socket = tlsSock;

    tlsSock.once('secureConnect', () => {
      this.phase = Phase.NLA_NEGOTIATE;
      const neg = buildNegotiate();
      this.negotiateMsg = neg;
      tlsSock.write(buildTsRequestToken(neg));
    });
    tlsSock.on('data', (chunk: Buffer) => this.onRawData(chunk));
    tlsSock.once('error', (e: Error) => this.emit('error', e));
    tlsSock.once('close', () => this.close());
  }

  // ── NLA / CredSSP ──────────────────────────────────────────────────────

  private handleNla(frame: Buffer): void {
    const resp = parseTsRequest(frame);

    if (this.phase === Phase.NLA_NEGOTIATE) {
      // Step 2: received NTLM Challenge → send NTLM Authenticate + pubKeyAuth (step 3)
      if (!resp.negoToken) { this.onError('No NTLM challenge in TSRequest'); return; }
      this.challengeMsg = resp.negoToken;
      const ch = parseChallenge(Buffer.from(this.challengeMsg));
      const { msg: authMsg, exportedSession } = buildAuthenticate(
        this.cfg.username, this.cfg.password, this.cfg.domain,
        ch, Buffer.from(this.negotiateMsg), Buffer.from(this.challengeMsg),
      );
      this.sealingCtx = new SealingContext(exportedSession);
      const pubKeyAuth = computePubKeyAuth(this.socket!, this.sealingCtx);
      this.phase = Phase.NLA_AUTHENTICATE;
      this.socket!.write(buildTsRequestAuth(authMsg, pubKeyAuth));

    } else if (this.phase === Phase.NLA_AUTHENTICATE) {
      // Step 4: received server's pubKeyAuth proof
      if (resp.errorCode) {
        this.onError(`CredSSP auth rejected by server (errorCode 0x${resp.errorCode.toString(16)})`);
        return;
      }
      // Step 5: send encrypted credentials (authInfo)
      if (!this.sealingCtx) { this.onError('No sealing context for authInfo'); return; }
      this.socket!.write(buildTsRequestAuthInfo(
        this.cfg.username, this.cfg.password, this.cfg.domain,
        this.sealingCtx,
      ));
      // Server does NOT respond to authInfo — CredSSP ends, MCS begins immediately
      console.log(`[rdp ${this.cfg.host}] CredSSP complete, sending MCS Connect-Initial`);
      this.phase = Phase.MCS_CONNECT;
      this.socket!.write(mcsConnectInitial(
        this.cfg.monitorWidth, this.cfg.monitorHeight,
        this.cfg.monitorCount, this.cfg.monitorWidth, this.cfg.monitorHeight,
      ));

    } else if (this.phase === Phase.NLA_CREDENTIALS) {
      // Should not happen; ignore
    }
  }

  // ── MCS connection ──────────────────────────────────────────────────────

  private onMcsResponse(frame: Buffer): void {
    console.log(`[rdp ${this.cfg.host}] MCS Connect-Response received`);
    const { ioChannelId } = parseMcsConnectResponse(stripX224(frame));
    this.ioChannelId = ioChannelId;
    this.phase = Phase.MCS_ERECT;
    this.socket!.write(mcsErectDomain());
    this.phase = Phase.MCS_ATTACH;
    this.socket!.write(mcsAttachUser());
  }

  private onMcsAttach(frame: Buffer): void {
    const p = stripX224(frame);
    const uid = parseMcsAttachUserConfirm(p);
    if (!uid) return;
    this.userId = uid;
    console.log(`[rdp ${this.cfg.host}] AttachUser userId=${uid}, joining channels`);
    this.phase = Phase.CHANNEL_JOIN;
    this.channelsToJoin = [this.userId, this.ioChannelId];
    this.channelsJoined = 0;
    this.socket!.write(mcsChannelJoin(this.userId, this.channelsToJoin[0]));
  }

  private onChannelJoin(frame: Buffer): void {
    void frame; // channel join confirms are not parsed
    this.channelsJoined++;
    if (this.channelsJoined < this.channelsToJoin.length) {
      this.socket!.write(mcsChannelJoin(this.userId, this.channelsToJoin[this.channelsJoined]));
    } else {
      console.log(`[rdp ${this.cfg.host}] Channels joined, sending ClientInfo`);
      this.phase = Phase.CLIENT_INFO;
      // Client Info PDU: security header (SEC_INFO_PKT=0x0040) + TS_INFO_PACKET
      const infoPacket = buildClientInfo(this.cfg.username, this.cfg.password, this.cfg.domain);
      this.socket!.write(mcsSend(this.userId, this.ioChannelId,
        Buffer.concat([secHdr(0x0040), infoPacket])));
    }
  }

  // ── Capability exchange ─────────────────────────────────────────────────

  private onCapabilities(frame: Buffer): void {
    const mcs = parseMcsSend(frame);
    if (!mcs) {
      console.log(`[rdp ${this.cfg.host}] Non-MCS frame in capabilities phase (first byte: 0x${frame[0].toString(16)})`);
      return;
    }
    let payload = mcs.payload;
    // Skip security header (4 bytes) if present
    if (payload.length > 4) payload = payload.slice(4);
    let sc: ReturnType<typeof parseShareCtrl>;
    try { sc = parseShareCtrl(payload); } catch { return; }
    if (sc.pduType !== PDU_TYPE_DEMAND_ACTIVE) return;

    this.shareId = sc.body.readUInt32LE(0);
    const totalW = this.cfg.monitorWidth * this.cfg.monitorCount;
    const caps   = buildCapabilities(totalW, this.cfg.monitorHeight);
    this.socket!.write(buildConfirmActive(this.shareId, this.userId, this.ioChannelId, caps));

    this.phase = Phase.SYNC_FINALIZE;
    this.socket!.write(buildSynchronize(this.shareId, this.userId, this.ioChannelId));
    this.socket!.write(buildControl(this.shareId, this.userId, this.ioChannelId, 4));
    this.socket!.write(buildControl(this.shareId, this.userId, this.ioChannelId, 1));
    this.socket!.write(buildFontList(this.shareId, this.userId, this.ioChannelId));
  }

  private onSyncFinalize(frame: Buffer): void {
    const mcs = parseMcsSend(frame);
    if (!mcs) return;
    try {
      const payload = mcs.payload.slice(4); // skip sec hdr
      const sc = parseShareCtrl(payload);
      if (sc.pduType === PDU_TYPE_DATA) {
        const { type2 } = parseShareData(sc.body);
        if (type2 === PDUTYPE2_FONTMAP) {
          this.phase = Phase.ACTIVE;
          this.emit('ready');
        }
      }
    } catch { /* absorb */ }
  }

  // ── Active: bitmap updates ──────────────────────────────────────────────

  private onActiveData(frame: Buffer): void {
    if (frame[0] !== 3) {
      this.handleFastPath(frame);
    } else {
      this.handleSlowPath(frame);
    }
  }

  private handleFastPath(frame: Buffer): void {
    let off = 1;
    const b1 = frame[off++];
    // 2-byte length when high bit set
    off += (b1 & 0x80) ? 1 : 0;

    while (off < frame.length) {
      const updateCode = frame[off++];
      const updateType = updateCode & 0x0f;
      if (off + 2 > frame.length) break;
      const updateLen = frame.readUInt16LE(off); off += 2;
      if (off + updateLen > frame.length) break;
      const updateData = frame.slice(off, off + updateLen); off += updateLen;

      if (updateType === 0x01) { // FASTPATH_UPDATETYPE_BITMAP
        for (const t of parseFpBitmap(updateData)) this.emit('bitmap', t);
      }
    }
  }

  private handleSlowPath(frame: Buffer): void {
    const mcs = parseMcsSend(frame);
    if (!mcs) return;
    try {
      const sc = parseShareCtrl(mcs.payload.slice(4));
      if (sc.pduType === PDU_TYPE_DATA) {
        const { type2, data } = parseShareData(sc.body);
        if (type2 === PDUTYPE2_UPDATE && data.readUInt16LE(0) === 0x0001) {
          for (const t of parseFpBitmap(data.slice(2))) this.emit('bitmap', t);
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
    this.tcp?.destroy();
    this.emit('close');
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────

function readDerLen(buf: Buffer, i: number): { len: number; consumed: number } {
  const b = buf[i];
  if (b < 0x80) return { len: b, consumed: 1 };
  const n = b & 0x7f;
  let len = 0;
  for (let k = 0; k < n; k++) len = (len << 8) | buf[i + 1 + k];
  return { len, consumed: 1 + n };
}
