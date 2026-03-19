import { useState } from 'react';
import type { ConnectParams, Protocol } from '../types';

interface Props {
  onConnect: (params: ConnectParams) => void;
}

export default function ConnectForm({ onConnect }: Props) {
  const [protocol, setProtocol] = useState<Protocol>('rdp');
  const [host,     setHost]     = useState('');
  const [port,     setPort]     = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [domain,   setDomain]   = useState('');
  const [monitors, setMonitors] = useState(1);
  const [width,    setWidth]    = useState(() => window.innerWidth);
  const [height,   setHeight]   = useState(() => window.innerHeight);
  const [ignoreCert, setIgnoreCert] = useState(true);
  const [viewOnly,   setViewOnly]   = useState(false);

  const defaultPort = protocol === 'rdp' ? 3389 : 5900;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    onConnect({
      protocol,
      host:     host.trim(),
      port:     parseInt(port) || defaultPort,
      username: username.trim(),
      password,
      domain:   domain.trim(),
      monitors,
      monitorWidth:  width,
      monitorHeight: height,
      colorDepth:    24,
      security:      'any',
      ignoreCert,
      viewOnly,
    });
  };

  return (
    <form className="connect-form" onSubmit={submit}>
      <h2>New Connection</h2>

      <div className="form-row protocol-row">
        <button type="button" className={`proto-btn ${protocol === 'rdp' ? 'active' : ''}`} onClick={() => setProtocol('rdp')}>RDP</button>
        <button type="button" className={`proto-btn ${protocol === 'vnc' ? 'active' : ''}`} onClick={() => setProtocol('vnc')}>VNC</button>
      </div>

      <div className="form-row">
        <label>Host</label>
        <input value={host} onChange={e => setHost(e.target.value)} placeholder="192.168.1.10" required />
      </div>

      <div className="form-row">
        <label>Port</label>
        <input value={port} onChange={e => setPort(e.target.value)} placeholder={String(defaultPort)} type="number" />
      </div>

      <div className="form-row">
        <label>Username</label>
        <input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" />
      </div>

      <div className="form-row">
        <label>Password</label>
        <input value={password} onChange={e => setPassword(e.target.value)} type="password" autoComplete="current-password" />
      </div>

      {protocol === 'rdp' && (
        <div className="form-row">
          <label>Domain</label>
          <input value={domain} onChange={e => setDomain(e.target.value)} placeholder="optional" />
        </div>
      )}

      <div className="form-section-label">Display</div>

      <div className="form-row">
        <label>Monitors</label>
        <div className="monitor-btns">
          {[1, 2, 3].map(n => (
            <button key={n} type="button" className={`monitor-btn ${monitors === n ? 'active' : ''}`} onClick={() => setMonitors(n)}>
              {n}
            </button>
          ))}
        </div>
      </div>

      <div className="form-row">
        <label>Resolution</label>
        <div className="res-row">
          <input value={width}  onChange={e => setWidth(parseInt(e.target.value) || 1920)}  type="number" className="res-input" />
          <span>×</span>
          <input value={height} onChange={e => setHeight(parseInt(e.target.value) || 1080)} type="number" className="res-input" />
        </div>
        <span className="form-hint">per monitor</span>
      </div>

      {protocol === 'rdp' && (
        <div className="form-row checkbox-row">
          <label>
            <input type="checkbox" checked={ignoreCert} onChange={e => setIgnoreCert(e.target.checked)} />
            Ignore certificate
          </label>
        </div>
      )}

      {protocol === 'vnc' && (
        <div className="form-row checkbox-row">
          <label>
            <input type="checkbox" checked={viewOnly} onChange={e => setViewOnly(e.target.checked)} />
            View only
          </label>
        </div>
      )}

      <button type="submit" className="connect-btn">Connect</button>
    </form>
  );
}
