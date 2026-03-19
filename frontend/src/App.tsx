import { useEffect, useRef, useState } from 'react';
import ConnectForm from './components/ConnectForm';
import MonitorView from './components/MonitorView';
import { getChannel, announceSession, requestMonitor, assignMonitor, endSession } from './lib/channel';
import type { ConnectParams, SessionInfo, ChannelMsg } from './types';
import './App.css';

const SERVER   = import.meta.env.VITE_SERVER_URL || '';
const WINDOW_ID = Math.random().toString(36).slice(2);

export default function App() {
  const [session,      setSession]      = useState<SessionInfo | null>(null);
  const [monitorIndex, setMonitorIndex] = useState<number | null>(null);
  const [isPrimary,    setIsPrimary]    = useState(false);
  const [showForm,     setShowForm]     = useState(false);
  const [error,        setError]        = useState('');

  const nextMonitorRef = useRef(1);
  const sessionRef     = useRef<SessionInfo | null>(null);
  sessionRef.current   = session;
  const isPrimaryRef   = useRef(false);

  useEffect(() => {
    const ch = getChannel();

    const handler = (e: MessageEvent<ChannelMsg>) => {
      const msg = e.data;

      if (msg.type === 'session-announce') {
        if (sessionRef.current) return;
        setSession(msg.session);
        setIsPrimary(false);
        requestMonitor(WINDOW_ID);
      }

      if (msg.type === 'monitor-assign' && msg.windowId === WINDOW_ID) {
        setMonitorIndex(msg.monitorIndex);
      }

      if (msg.type === 'monitor-request') {
        if (!isPrimaryRef.current || !sessionRef.current) return;
        const idx = nextMonitorRef.current;
        nextMonitorRef.current = idx + 1;
        assignMonitor(msg.windowId, idx);
      }

      if (msg.type === 'session-end') {
        setSession(null);
        setMonitorIndex(null);
        setShowForm(false);
      }
    };

    ch.addEventListener('message', handler);

    const timeout = setTimeout(() => {
      if (!sessionRef.current) setShowForm(true);
    }, 300);

    const reannounce = setInterval(() => {
      if (isPrimaryRef.current && sessionRef.current) {
        announceSession(sessionRef.current);
      }
    }, 5000);

    return () => {
      ch.removeEventListener('message', handler);
      clearTimeout(timeout);
      clearInterval(reannounce);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleConnect = async (params: ConnectParams) => {
    setError('');
    try {
      const res = await fetch(`${SERVER}/api/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      });
      if (!res.ok) throw new Error(await res.text());
      const info = await res.json() as SessionInfo;

      isPrimaryRef.current = true;
      setIsPrimary(true);
      setSession(info);
      setMonitorIndex(0);
      nextMonitorRef.current = 1;
      setShowForm(false);

      announceSession(info);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed');
    }
  };

  const handleDisconnect = () => {
    if (isPrimaryRef.current) endSession();
    setSession(null);
    setMonitorIndex(null);
    setShowForm(true);
    isPrimaryRef.current = false;
    nextMonitorRef.current = 1;
  };

  // ── Render ──────────────────────────────────────────────────────────────

  if (session && monitorIndex !== null) {
    return (
      <div className="monitor-root">
        <MonitorView
          session={session}
          monitorIndex={monitorIndex}
          onDisconnect={handleDisconnect}
        />
        {isPrimary && (
          <div className="monitor-hud">
            <span className="hud-label">Monitor {monitorIndex + 1}</span>
            <span className="hud-hint">Open a new browser window for each additional monitor</span>
            <button className="hud-disconnect" onClick={handleDisconnect}>Disconnect</button>
          </div>
        )}
        {!isPrimary && (
          <div className="monitor-hud secondary">
            <span className="hud-label">Monitor {monitorIndex + 1}</span>
          </div>
        )}
      </div>
    );
  }

  if (session && monitorIndex === null) {
    return (
      <div className="waiting">
        <div className="waiting-spinner" />
        <div>Waiting for monitor assignment…</div>
      </div>
    );
  }

  if (showForm) {
    return (
      <div className="form-root">
        <ConnectForm onConnect={handleConnect} />
        {error && <div className="form-error">{error}</div>}
      </div>
    );
  }

  return (
    <div className="waiting">
      <div className="waiting-spinner" />
      <div>Looking for active session…</div>
    </div>
  );
}
