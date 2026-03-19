import { useEffect, useRef, useState } from 'react';
import ConnectForm from './components/ConnectForm';
import MonitorView from './components/MonitorView';
import { getChannel, announceSession, requestMonitor, assignMonitor, endSession } from './lib/channel';
import type { ConnectParams, SessionInfo, ChannelMsg } from './types';
import './App.css';

const SERVER = import.meta.env.VITE_SERVER_URL || '';
const WINDOW_ID = Math.random().toString(36).slice(2);

export default function App() {
  const [session,      setSession]      = useState<SessionInfo | null>(null);
  const [monitorIndex, setMonitorIndex] = useState<number | null>(null);
  const [isPrimary,    setIsPrimary]    = useState(false);
  const [showForm,     setShowForm]     = useState(false);
  const [error,        setError]        = useState('');

  // Track assigned secondary windows so primary can assign correct index
  const nextMonitorRef  = useRef(1);  // 0 = primary, starts assigning from 1
  const sessionRef      = useRef<SessionInfo | null>(null);
  sessionRef.current    = session;

  useEffect(() => {
    const ch = getChannel();

    const handler = (e: MessageEvent<ChannelMsg>) => {
      const msg = e.data;

      // Another window already has a session → join as secondary
      if (msg.type === 'session-announce') {
        if (sessionRef.current) return; // already connected
        setSession(msg.session);
        setIsPrimary(false);
        requestMonitor(WINDOW_ID);
      }

      // Primary assigns us a monitor index
      if (msg.type === 'monitor-assign' && msg.windowId === WINDOW_ID) {
        setMonitorIndex(msg.monitorIndex);
      }

      // A secondary window is asking for a monitor slot
      if (msg.type === 'monitor-request') {
        if (!isPrimaryRef.current || !sessionRef.current) return;
        const idx = nextMonitorRef.current;
        if (idx < sessionRef.current.monitors) {
          nextMonitorRef.current = idx + 1;
          assignMonitor(msg.windowId, idx);
        }
      }

      // Session ended
      if (msg.type === 'session-end') {
        setSession(null);
        setMonitorIndex(null);
        setShowForm(false);
      }
    };

    ch.addEventListener('message', handler);

    // On load: check if a session already exists by requesting from channel
    // Give it 300 ms — if no session-announce arrives we're the first window
    const timeout = setTimeout(() => {
      if (!sessionRef.current) setShowForm(true);
    }, 300);

    // Re-announce if this is primary (handles secondary window refresh)
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

  // Keep a ref so the closure above can read current isPrimary
  const isPrimaryRef = useRef(false);

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

      // Tell other open windows about this session
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
  };

  // ── Render ──────────────────────────────────────────────────────────────────

  // Active monitor view
  if (session && monitorIndex !== null) {
    return (
      <div className="monitor-root">
        <MonitorView
          session={session}
          monitorIndex={monitorIndex}
          isPrimary={isPrimary}
          onDisconnect={handleDisconnect}
        />
        {isPrimary && (
          <div className="monitor-hud">
            <span className="hud-label">Monitor {monitorIndex + 1} / {session.monitors}</span>
            {session.monitors > 1 && (
              <span className="hud-hint">Open a new browser window for each additional monitor</span>
            )}
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

  // Waiting for monitor assignment (secondary window not yet assigned)
  if (session && monitorIndex === null) {
    return (
      <div className="waiting">
        <div className="waiting-spinner" />
        <div>Waiting for monitor assignment…</div>
      </div>
    );
  }

  // Connect form (primary window before connection)
  if (showForm) {
    return (
      <div className="form-root">
        <ConnectForm onConnect={handleConnect} />
        {error && <div className="form-error">{error}</div>}
      </div>
    );
  }

  // Brief loading state while checking for existing sessions
  return (
    <div className="waiting">
      <div className="waiting-spinner" />
      <div>Looking for active session…</div>
    </div>
  );
}
