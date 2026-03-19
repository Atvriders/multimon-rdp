import { useEffect, useRef } from 'react';
import Guacamole from 'guacamole-common-js';
import { RDPTunnel, BroadcastTunnel } from '../lib/tunnel';
import { getChannel, sendMouse, sendKey, endSession } from '../lib/channel';
import type { SessionInfo, ChannelMsg } from '../types';

interface Props {
  session:      SessionInfo;
  monitorIndex: number;   // which monitor this window shows (0-based)
  isPrimary:    boolean;  // true → owns the WebSocket connection
  onDisconnect: () => void;
}

export default function MonitorView({ session, monitorIndex, isPrimary, onDisconnect }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // ── Build Guacamole client ───────────────────────────────────────────────
    const tunnel = isPrimary
      ? new RDPTunnel(window.location.href, session.token)
      : new BroadcastTunnel();

    const client = new Guacamole.Client(tunnel);
    const display = client.getDisplay();
    const el = display.getElement();

    el.style.position = 'absolute';
    el.style.top      = '0';
    el.style.transformOrigin = '0 0';
    container.appendChild(el);

    // ── Scale + offset ───────────────────────────────────────────────────────
    // For monitor N at monitorWidth W: shift the canvas left by N*W*scale
    // so only this monitor's slice is visible in the container viewport.
    const scaleDisplay = () => {
      const dh = display.getHeight();
      if (!dh) return;
      const scale = container.clientHeight / dh;
      display.scale(scale);
      el.style.left = `-${monitorIndex * session.monitorWidth * scale}px`;
    };
    display.onresize = scaleDisplay;
    const ro = new ResizeObserver(scaleDisplay);
    ro.observe(container);

    // ── Mouse ────────────────────────────────────────────────────────────────
    const onMouse = (e: MouseEvent) => {
      e.preventDefault();
      const dh = display.getHeight();
      const s  = dh ? container.clientHeight / dh : 1;
      const rect = el.getBoundingClientRect();
      const x = Math.round((e.clientX - rect.left) / s);
      const y = Math.round((e.clientY - rect.top)  / s);
      if (isPrimary) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        client.sendMouseState(new (Guacamole.Mouse.State as any)(
          x, y,
          (e.buttons & 1) !== 0,
          (e.buttons & 4) !== 0,
          (e.buttons & 2) !== 0,
          false, false,
        ));
      } else {
        sendMouse(x, y, e.buttons, false, false);
      }
    };
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const dh = display.getHeight();
      const s  = dh ? container.clientHeight / dh : 1;
      const rect = el.getBoundingClientRect();
      const x = Math.round((e.clientX - rect.left) / s);
      const y = Math.round((e.clientY - rect.top)  / s);
      if (isPrimary) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        client.sendMouseState(new (Guacamole.Mouse.State as any)(
          x, y, false, false, false, e.deltaY < 0, e.deltaY > 0,
        ));
      } else {
        sendMouse(x, y, 0, e.deltaY < 0, e.deltaY > 0);
      }
    };
    el.addEventListener('mousemove',   onMouse);
    el.addEventListener('mousedown',   onMouse);
    el.addEventListener('mouseup',     onMouse);
    el.addEventListener('contextmenu', ev => ev.preventDefault());
    el.addEventListener('wheel',       onWheel, { passive: false });

    // ── Keyboard ─────────────────────────────────────────────────────────────
    const keyboard = new Guacamole.Keyboard(document);
    if (isPrimary) {
      keyboard.onkeydown = (k: number) => client.sendKeyEvent(1, k);
      keyboard.onkeyup   = (k: number) => client.sendKeyEvent(0, k);
    } else {
      keyboard.onkeydown = (k: number) => sendKey(k, true);
      keyboard.onkeyup   = (k: number) => sendKey(k, false);
    }

    // ── Secondary: receive input forwarded from primary's BroadcastChannel ──
    let chCleanup: (() => void) | undefined;
    if (isPrimary) {
      const ch = getChannel();
      const handler = (e: MessageEvent<ChannelMsg>) => {
        const msg = e.data;
        if (msg.type === 'mouse') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          client.sendMouseState(new (Guacamole.Mouse.State as any)(
            msg.x, msg.y,
            (msg.buttons & 1) !== 0,
            (msg.buttons & 4) !== 0,
            (msg.buttons & 2) !== 0,
            msg.up, msg.down,
          ));
        }
        if (msg.type === 'key') {
          client.sendKeyEvent(msg.pressed ? 1 : 0, msg.keysym);
        }
      };
      ch.addEventListener('message', handler);
      chCleanup = () => ch.removeEventListener('message', handler);
    } else {
      // Secondary: feed guac-data into BroadcastTunnel
      const ch = getChannel();
      const handler = (e: MessageEvent<ChannelMsg>) => {
        if (e.data.type === 'guac-data') {
          (tunnel as BroadcastTunnel).receiveData(e.data.data);
        }
        if (e.data.type === 'session-end') {
          onDisconnect();
        }
      };
      ch.addEventListener('message', handler);
      chCleanup = () => ch.removeEventListener('message', handler);
    }

    // ── Connection state ─────────────────────────────────────────────────────
    client.onerror = () => onDisconnect();
    client.onstatechange = (state: number) => {
      if (state === 5) onDisconnect();
    };

    client.connect('');

    return () => {
      chCleanup?.();
      keyboard.onkeydown = null;
      keyboard.onkeyup   = null;
      ro.disconnect();
      client.disconnect();
      if (el.parentNode === container) container.removeChild(el);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      ref={containerRef}
      style={{ position: 'absolute', inset: 0, background: '#000', overflow: 'hidden' }}
    />
  );
}
