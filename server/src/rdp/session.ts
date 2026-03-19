/**
 * Session manager.
 * One RDP session can have 1-3 browser windows.
 * When a new browser window joins increasing the monitor count,
 * the RDP session reconnects with the higher monitor count.
 */
import { RdpClient, RdpConfig } from './client';
import { BitmapTile } from './bitmap';
import type WebSocket from 'ws';
import * as crypto from 'crypto';

// ── Wire message types (server → browser) ────────────────────────────────

const MSG_BITMAP    = 1;
const MSG_READY     = 2;
const MSG_CLOSE     = 3;
const MSG_RECONNECT = 4;
const MSG_ERROR     = 5;

function bitmapFrame(monitorIndex: number, tile: BitmapTile): Buffer {
  // [type 1][monitorIdx 2][x 2][y 2][w 2][h 2][rgba N]
  const hdr = Buffer.alloc(11);
  hdr[0] = MSG_BITMAP;
  hdr.writeUInt16LE(monitorIndex, 1);
  hdr.writeUInt16LE(tile.x, 3);
  hdr.writeUInt16LE(tile.y, 5);
  hdr.writeUInt16LE(tile.width, 7);
  hdr.writeUInt16LE(tile.height, 9);
  return Buffer.concat([hdr, tile.rgba]);
}

function readyFrame(monitorIndex: number, monitorWidth: number, monitorHeight: number): Buffer {
  const buf = Buffer.alloc(7);
  buf[0] = MSG_READY;
  buf.writeUInt16LE(monitorIndex, 1);
  buf.writeUInt16LE(monitorWidth, 3);
  buf.writeUInt16LE(monitorHeight, 5);
  return buf;
}

function reconnectFrame(): Buffer {
  return Buffer.from([MSG_RECONNECT]);
}

function closeFrame(): Buffer {
  return Buffer.from([MSG_CLOSE]);
}

function errorFrame(message: string): Buffer {
  const msgBuf = Buffer.from(message, 'utf8');
  const buf = Buffer.alloc(3 + msgBuf.length);
  buf[0] = MSG_ERROR;
  buf.writeUInt16LE(msgBuf.length, 1);
  msgBuf.copy(buf, 3);
  return buf;
}

// ── Session ───────────────────────────────────────────────────────────────

interface BrowserSocket {
  ws:           WebSocket;
  monitorIndex: number;
}

export class RdpSession {
  readonly sessionId: string;
  private cfg:        RdpConfig;
  private rdp:        RdpClient | null = null;
  private sockets:    Map<number, BrowserSocket> = new Map();
  private reconnecting = false;

  // Full in-memory framebuffer (total width × height × RGBA)
  private framebuf: Buffer;
  private totalWidth: number;

  constructor(cfg: RdpConfig) {
    this.sessionId = crypto.randomUUID();
    this.cfg       = { ...cfg };
    this.totalWidth = cfg.monitorWidth * cfg.monitorCount;
    this.framebuf  = Buffer.alloc(this.totalWidth * cfg.monitorHeight * 4, 0);
    this.startRdp();
  }

  get monitorWidth()  { return this.cfg.monitorWidth; }
  get monitorHeight() { return this.cfg.monitorHeight; }
  get monitorCount()  { return this.cfg.monitorCount; }

  // ── Browser WebSocket registration ──────────────────────────────────────

  addSocket(ws: WebSocket, monitorIndex: number): void {
    // If monitorIndex >= current count → need to reconnect with more monitors
    if (monitorIndex >= this.cfg.monitorCount) {
      const newCount = monitorIndex + 1;
      console.log(`[session ${this.sessionId}] Adding monitor ${monitorIndex}, reconnecting with ${newCount} monitors`);
      this.reconnectWithMonitors(newCount, ws, monitorIndex);
      return;
    }

    this.sockets.set(monitorIndex, { ws, monitorIndex });
    ws.send(readyFrame(monitorIndex, this.cfg.monitorWidth, this.cfg.monitorHeight));

    // Send current framebuffer state for this monitor
    this.sendCurrentFrame(monitorIndex, ws);

    ws.on('message', (data: Buffer | string) => this.onBrowserMsg(data, monitorIndex));
    ws.on('close', () => { this.sockets.delete(monitorIndex); });
  }

  removeSocket(monitorIndex: number): void {
    this.sockets.delete(monitorIndex);
  }

  // ── RDP reconnect for more monitors ────────────────────────────────────

  private reconnectWithMonitors(newCount: number, pendingWs: WebSocket, pendingMonitorIdx: number): void {
    if (this.reconnecting) return;
    this.reconnecting = true;

    // Notify all connected browsers
    this.broadcast(reconnectFrame());

    this.cfg = { ...this.cfg, monitorCount: newCount };
    this.totalWidth = this.cfg.monitorWidth * newCount;
    // Grow framebuffer
    const oldBuf = this.framebuf;
    this.framebuf = Buffer.alloc(this.totalWidth * this.cfg.monitorHeight * 4, 0);
    // Copy existing content for monitors 0..n-1
    oldBuf.copy(this.framebuf, 0, 0, Math.min(oldBuf.length, this.framebuf.length));

    this.rdp?.disconnect();
    this.rdp = null;

    setTimeout(() => {
      this.reconnecting = false;
      this.startRdp(() => {
        // After reconnect: re-send READY to all existing browsers
        for (const [idx, bs] of this.sockets) {
          bs.ws.send(readyFrame(idx, this.cfg.monitorWidth, this.cfg.monitorHeight));
        }
        // Add the pending new browser socket
        this.sockets.set(pendingMonitorIdx, { ws: pendingWs, monitorIndex: pendingMonitorIdx });
        pendingWs.send(readyFrame(pendingMonitorIdx, this.cfg.monitorWidth, this.cfg.monitorHeight));
        pendingWs.on('message', (data: Buffer | string) => this.onBrowserMsg(data, pendingMonitorIdx));
        pendingWs.on('close', () => { this.sockets.delete(pendingMonitorIdx); });
      });
    }, 500);
  }

  // ── Start RDP connection ─────────────────────────────────────────────────

  private startRdp(onReady?: () => void): void {
    const rdp = new RdpClient(this.cfg);

    rdp.on('ready', () => {
      console.log(`[rdp ${this.cfg.host}] ACTIVE — ${this.cfg.monitorCount} monitor(s)`);
      onReady?.();
    });

    rdp.on('bitmap', (tile: BitmapTile) => {
      this.applyTile(tile);
    });

    rdp.on('error', (e: Error) => {
      console.error(`[rdp ${this.cfg.host}] Error:`, e.message);
      if (!this.reconnecting) this.broadcast(errorFrame(e.message));
    });

    rdp.on('close', () => {
      console.log(`[rdp ${this.cfg.host}] Disconnected`);
      if (!this.reconnecting) this.broadcast(closeFrame());
    });

    this.rdp = rdp;
    rdp.connect();
  }

  // ── Tile distribution ────────────────────────────────────────────────────

  private applyTile(tile: BitmapTile): void {
    // Apply to in-memory framebuffer
    const monW = this.cfg.monitorWidth;
    const monH = this.cfg.monitorHeight;

    // Write to framebuf (clamped to bounds)
    const fw = this.totalWidth;
    for (let row = 0; row < tile.height; row++) {
      const fbRow = tile.y + row;
      if (fbRow >= monH) break;
      const srcOff = row * tile.width * 4;
      const dstOff = (fbRow * fw + tile.x) * 4;
      tile.rgba.copy(this.framebuf, dstOff, srcOff, srcOff + tile.width * 4);
    }

    // Determine which monitor(s) this tile touches
    const tileLeft  = tile.x;
    const tileRight = tile.x + tile.width;

    for (const [idx, bs] of this.sockets) {
      const monLeft  = idx * monW;
      const monRight = monLeft + monW;

      // Check intersection
      if (tileRight <= monLeft || tileLeft >= monRight) continue;

      // Clip tile to monitor bounds
      const clipLeft  = Math.max(tileLeft,  monLeft)  - monLeft;
      const clipRight = Math.min(tileRight, monRight) - monLeft;
      const clipW     = clipRight - clipLeft;
      if (clipW <= 0) continue;

      // Build clipped RGBA
      const clippedRgba = Buffer.alloc(clipW * tile.height * 4);
      const srcMonOff   = Math.max(tileLeft, monLeft) - tileLeft;
      for (let row = 0; row < tile.height; row++) {
        const srcOff = (row * tile.width + srcMonOff) * 4;
        const dstOff = row * clipW * 4;
        tile.rgba.copy(clippedRgba, dstOff, srcOff, srcOff + clipW * 4);
      }

      const clippedTile: BitmapTile = {
        x:      clipLeft,
        y:      tile.y,
        width:  clipW,
        height: tile.height,
        rgba:   clippedRgba,
      };

      if (bs.ws.readyState === 1 /* OPEN */) {
        bs.ws.send(bitmapFrame(idx, clippedTile), { binary: true });
      }
    }
  }

  private sendCurrentFrame(monitorIndex: number, ws: WebSocket): void {
    const monW = this.cfg.monitorWidth;
    const monH = this.cfg.monitorHeight;
    const fw   = this.totalWidth;
    const monX = monitorIndex * monW;

    // Send the current framebuffer for this monitor as one tile
    const rgba = Buffer.alloc(monW * monH * 4);
    for (let row = 0; row < monH; row++) {
      const srcOff = (row * fw + monX) * 4;
      const dstOff = row * monW * 4;
      this.framebuf.copy(rgba, dstOff, srcOff, srcOff + monW * 4);
    }
    const tile: BitmapTile = { x: 0, y: 0, width: monW, height: monH, rgba };
    ws.send(bitmapFrame(monitorIndex, tile), { binary: true });
  }

  // ── Browser input ────────────────────────────────────────────────────────

  private onBrowserMsg(data: Buffer | string, monitorIndex: number): void {
    try {
      const msg = JSON.parse(data.toString()) as Record<string, unknown>;
      const monOffsetX = monitorIndex * this.cfg.monitorWidth;

      switch (msg.type) {
        case 'mouse': {
          const x = (msg.x as number) + monOffsetX;
          const y = msg.y as number;
          this.rdp?.sendMouse(x, y, msg.buttons as number);
          break;
        }
        case 'wheel': {
          const x = (msg.x as number) + monOffsetX;
          this.rdp?.sendMouse(x, msg.y as number, 0, msg.delta as number);
          break;
        }
        case 'key': {
          this.rdp?.sendKey(msg.scancode as number, msg.down as boolean);
          break;
        }
      }
    } catch { /* ignore bad JSON */ }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  private broadcast(frame: Buffer): void {
    for (const bs of this.sockets.values()) {
      if (bs.ws.readyState === 1) bs.ws.send(frame, { binary: true });
    }
  }

  destroy(): void {
    this.broadcast(closeFrame());
    this.rdp?.disconnect();
    this.sockets.clear();
  }
}

// ── Session registry ──────────────────────────────────────────────────────

export class SessionRegistry {
  private sessions: Map<string, RdpSession> = new Map();

  create(cfg: RdpConfig): RdpSession {
    const s = new RdpSession(cfg);
    this.sessions.set(s.sessionId, s);
    return s;
  }

  get(id: string): RdpSession | undefined {
    return this.sessions.get(id);
  }

  delete(id: string): void {
    this.sessions.get(id)?.destroy();
    this.sessions.delete(id);
  }
}
