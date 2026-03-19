import { useState } from 'react';
import type { ConnectParams } from '../types';

interface Props {
  onConnect: (params: ConnectParams) => void;
}

export default function ConnectForm({ onConnect }: Props) {
  const [host,     setHost]     = useState('');
  const [port,     setPort]     = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [domain,   setDomain]   = useState('');
  const [width,    setWidth]    = useState(1920);
  const [height,   setHeight]   = useState(1080);
  const [ignoreCert, setIgnoreCert] = useState(true);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    onConnect({
      host:         host.trim(),
      port:         parseInt(port) || 3389,
      username:     username.trim(),
      password,
      domain:       domain.trim(),
      monitorWidth:  width,
      monitorHeight: height,
      ignoreCert,
    });
  };

  return (
    <form className="connect-form" onSubmit={submit}>
      <h2>Connect</h2>

      <div className="form-row">
        <label>Host</label>
        <input value={host} onChange={e => setHost(e.target.value)} placeholder="192.168.1.10" required />
      </div>

      <div className="form-row">
        <label>Port</label>
        <input value={port} onChange={e => setPort(e.target.value)} placeholder="3389" type="number" />
      </div>

      <div className="form-row">
        <label>Username</label>
        <input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" />
      </div>

      <div className="form-row">
        <label>Password</label>
        <input value={password} onChange={e => setPassword(e.target.value)} type="password" autoComplete="current-password" />
      </div>

      <div className="form-row">
        <label>Domain</label>
        <input value={domain} onChange={e => setDomain(e.target.value)} placeholder="optional" />
      </div>

      <div className="form-section-label">Resolution per monitor</div>

      <div className="form-row">
        <label>Resolution</label>
        <div className="res-row">
          <input value={width}  onChange={e => setWidth(parseInt(e.target.value) || 1920)}  type="number" className="res-input" />
          <span>×</span>
          <input value={height} onChange={e => setHeight(parseInt(e.target.value) || 1080)} type="number" className="res-input" />
        </div>
        <span className="form-hint">Open a new window for each additional monitor</span>
      </div>

      <div className="form-row checkbox-row">
        <label>
          <input type="checkbox" checked={ignoreCert} onChange={e => setIgnoreCert(e.target.checked)} />
          Ignore certificate
        </label>
      </div>

      <button type="submit" className="connect-btn">Connect</button>
    </form>
  );
}
