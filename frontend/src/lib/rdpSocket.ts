/**
 * Browser-side WebSocket connection to the RDP session.
 * Receives binary bitmap tiles, emits them for canvas rendering.
 * Sends mouse/keyboard input as JSON.
 */

const SERVER = import.meta.env.VITE_SERVER_URL || '';

// ── Binary frame types (must match server/src/rdp/session.ts) ────────────

const MSG_BITMAP    = 1;
const MSG_READY     = 2;
const MSG_CLOSE     = 3;
const MSG_RECONNECT = 4;

export interface BitmapUpdate {
  x:      number;
  y:      number;
  width:  number;
  height: number;
  rgba:   Uint8ClampedArray;
}

export interface ReadyInfo {
  monitorIndex:  number;
  monitorWidth:  number;
  monitorHeight: number;
}

// ── keysym / scancode map ─────────────────────────────────────────────────
// Map browser KeyboardEvent.code → RDP scancode

const SCANCODE: Record<string, number> = {
  Escape:28, F1:59, F2:60, F3:61, F4:62, F5:63, F6:64, F7:65, F8:66, F9:67, F10:68, F11:87, F12:88,
  Backquote:41, Digit1:2, Digit2:3, Digit3:4, Digit4:5, Digit5:6, Digit6:7, Digit7:8, Digit8:9,
  Digit9:10, Digit0:11, Minus:12, Equal:13, Backspace:14,
  Tab:15, KeyQ:16, KeyW:17, KeyE:18, KeyR:19, KeyT:20, KeyY:21, KeyU:22, KeyI:23, KeyO:24,
  KeyP:25, BracketLeft:26, BracketRight:27, Backslash:43, CapsLock:58,
  KeyA:30, KeyS:31, KeyD:32, KeyF:33, KeyG:34, KeyH:35, KeyJ:36, KeyK:37, KeyL:38,
  Semicolon:39, Quote:40, Enter:28,
  ShiftLeft:42, KeyZ:44, KeyX:45, KeyC:46, KeyV:47, KeyB:48, KeyN:49, KeyM:50,
  Comma:51, Period:52, Slash:53, ShiftRight:54,
  ControlLeft:29, MetaLeft:91, AltLeft:56, Space:57, AltRight:56, MetaRight:92,
  ContextMenu:93, ControlRight:29,
  Insert:82, Home:71, PageUp:73, Delete:83, End:79, PageDown:81,
  ArrowUp:72, ArrowLeft:75, ArrowDown:80, ArrowRight:77,
  NumLock:69, NumpadDivide:53, NumpadMultiply:55, NumpadSubtract:74,
  Numpad7:71, Numpad8:72, Numpad9:73, NumpadAdd:78,
  Numpad4:75, Numpad5:76, Numpad6:77,
  Numpad1:79, Numpad2:80, Numpad3:81, NumpadEnter:28,
  Numpad0:82, NumpadDecimal:83,
  PrintScreen:55, ScrollLock:70, Pause:69,
};

export function codeToScancode(code: string): number {
  return SCANCODE[code] ?? 0;
}

// ── RdpSocket ─────────────────────────────────────────────────────────────

export class RdpSocket {
  private ws: WebSocket | null = null;
  private sessionId: string;
  private monitorIndex: number;
  private onBitmap: (update: BitmapUpdate) => void;
  private onReady:  (info: ReadyInfo) => void;
  private onClose:  () => void;
  private onReconnect: () => void;

  constructor(opts: {
    sessionId:    string;
    monitorIndex: number;
    onBitmap:     (update: BitmapUpdate) => void;
    onReady:      (info: ReadyInfo) => void;
    onClose:      () => void;
    onReconnect:  () => void;
  }) {
    this.sessionId    = opts.sessionId;
    this.monitorIndex = opts.monitorIndex;
    this.onBitmap     = opts.onBitmap;
    this.onReady      = opts.onReady;
    this.onClose      = opts.onClose;
    this.onReconnect  = opts.onReconnect;
    this.connect();
  }

  private connect(): void {
    const base = SERVER.replace(/^http/, 'ws').replace(/\/$/, '');
    const url  = `${base}/ws?sessionId=${this.sessionId}&monitor=${this.monitorIndex}`;
    const ws   = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    this.ws = ws;

    ws.onmessage = (e) => {
      if (typeof e.data === 'string') return;
      const buf = new DataView(e.data as ArrayBuffer);
      const type = buf.getUint8(0);

      if (type === MSG_BITMAP) {
        const x       = buf.getUint16(3, true);
        const y       = buf.getUint16(5, true);
        const width   = buf.getUint16(7, true);
        const height  = buf.getUint16(9, true);
        const rgba    = new Uint8ClampedArray(e.data as ArrayBuffer, 11);
        this.onBitmap({ x, y, width, height, rgba });
      } else if (type === MSG_READY) {
        const monitorIndex  = buf.getUint16(1, true);
        const monitorWidth  = buf.getUint16(3, true);
        const monitorHeight = buf.getUint16(5, true);
        this.onReady({ monitorIndex, monitorWidth, monitorHeight });
      } else if (type === MSG_CLOSE) {
        this.onClose();
      } else if (type === MSG_RECONNECT) {
        this.onReconnect();
      }
    };

    ws.onclose = () => this.onClose();
    ws.onerror = () => this.onClose();
  }

  sendMouse(x: number, y: number, buttons: number): void {
    this.send(JSON.stringify({ type: 'mouse', x, y, buttons }));
  }

  sendWheel(x: number, y: number, delta: number): void {
    this.send(JSON.stringify({ type: 'wheel', x, y, delta }));
  }

  sendKey(scancode: number, down: boolean): void {
    this.send(JSON.stringify({ type: 'key', scancode, down }));
  }

  private send(data: string): void {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(data);
  }

  disconnect(): void {
    this.ws?.close();
    this.ws = null;
  }
}
