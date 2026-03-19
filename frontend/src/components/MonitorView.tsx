import { useEffect, useRef, useState } from 'react';
import { RdpSocket, codeToScancode } from '../lib/rdpSocket';
import type { SessionInfo } from '../types';

interface Props {
  session:      SessionInfo;
  monitorIndex: number;
  isPrimary:    boolean;
  onDisconnect: () => void;
}

export default function MonitorView({ session, monitorIndex, isPrimary, onDisconnect }: Props) {
  const canvasRef   = useRef<HTMLCanvasElement>(null);
  const socketRef   = useRef<RdpSocket | null>(null);
  const [reconnecting, setReconnecting] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d')!;
    canvas.width  = session.monitorWidth;
    canvas.height = session.monitorHeight;

    const sock = new RdpSocket({
      sessionId:    session.sessionId,
      monitorIndex,
      onBitmap: ({ x, y, width, height, rgba }) => {
        if (width <= 0 || height <= 0) return;
        const imgData = new ImageData(rgba, width, height);
        ctx.putImageData(imgData, x, y);
      },
      onReady: ({ monitorWidth, monitorHeight }) => {
        canvas.width  = monitorWidth;
        canvas.height = monitorHeight;
        setReconnecting(false);
      },
      onClose:      onDisconnect,
      onReconnect:  () => setReconnecting(true),
    });
    socketRef.current = sock;

    // ── Mouse ─────────────────────────────────────────────────────────────
    const getPos = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const scaleX = canvas.width  / rect.width;
      const scaleY = canvas.height / rect.height;
      return {
        x: Math.round((e.clientX - rect.left) * scaleX),
        y: Math.round((e.clientY - rect.top)  * scaleY),
      };
    };

    const onMouse = (e: MouseEvent) => {
      e.preventDefault();
      const { x, y } = getPos(e);
      sock.sendMouse(x, y, e.buttons);
    };

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const { x, y } = getPos(e);
      sock.sendWheel(x, y, e.deltaY);
    };

    canvas.addEventListener('mousemove',   onMouse);
    canvas.addEventListener('mousedown',   onMouse);
    canvas.addEventListener('mouseup',     onMouse);
    canvas.addEventListener('contextmenu', (e: Event) => e.preventDefault());
    canvas.addEventListener('wheel',       onWheel, { passive: false });

    // ── Keyboard ──────────────────────────────────────────────────────────
    const onKeyDown = (e: KeyboardEvent) => {
      // Don't capture browser shortcuts (F5, Ctrl+W, etc.) that could break the page
      if (e.key === 'F5') return;
      e.preventDefault();
      const sc = codeToScancode(e.code);
      if (sc) sock.sendKey(sc, true);
    };
    const onKeyUp = (e: KeyboardEvent) => {
      const sc = codeToScancode(e.code);
      if (sc) sock.sendKey(sc, false);
    };

    canvas.addEventListener('keydown', onKeyDown);
    canvas.addEventListener('keyup',   onKeyUp);
    canvas.setAttribute('tabindex', '0');

    return () => {
      sock.disconnect();
      socketRef.current = null;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div style={{ position: 'absolute', inset: 0, background: '#000', overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      {reconnecting && (
        <div className="waiting" style={{ position: 'absolute', zIndex: 10, background: 'rgba(0,0,0,0.7)' }}>
          <div className="waiting-spinner" />
          <div>Reconnecting…</div>
        </div>
      )}
      <canvas
        ref={canvasRef}
        style={{ width: '100%', height: '100%', objectFit: 'contain', cursor: 'none', display: 'block' }}
        onClick={() => canvasRef.current?.focus()}
      />
    </div>
  );
}
