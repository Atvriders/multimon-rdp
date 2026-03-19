import * as http from 'http';
import { WebSocketServer } from 'ws';
import { SessionRegistry } from './rdp/session';
import type { RdpConfig } from './rdp/client';

const PORT = parseInt(process.env.PORT ?? '3001', 10);

const registry = new SessionRegistry();

// ── HTTP server ───────────────────────────────────────────────────────────

const httpServer = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (req.method === 'POST' && req.url === '/api/connect') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const p = JSON.parse(body) as {
          host: string; port?: number;
          username?: string; password?: string; domain?: string;
          monitorWidth: number; monitorHeight: number;
          ignoreCert?: boolean;
        };
        if (!p.host) { res.writeHead(400); res.end('Missing host'); return; }

        const cfg: RdpConfig = {
          host:         p.host,
          port:         p.port ?? 3389,
          username:     p.username ?? '',
          password:     p.password ?? '',
          domain:       p.domain   ?? '',
          monitorWidth:  p.monitorWidth  || 1920,
          monitorHeight: p.monitorHeight || 1080,
          monitorCount:  1,   // always start with 1 monitor
          ignoreCert:   p.ignoreCert !== false,
        };

        const session = registry.create(cfg);
        console.log(`[connect] ${cfg.username}@${cfg.host} → session ${session.sessionId}`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          sessionId:     session.sessionId,
          monitorWidth:  cfg.monitorWidth,
          monitorHeight: cfg.monitorHeight,
          monitors:      1,
        }));
      } catch {
        res.writeHead(400); res.end('Invalid JSON');
      }
    });
    return;
  }

  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  res.writeHead(404); res.end();
});

// ── WebSocket server ──────────────────────────────────────────────────────

const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

wss.on('connection', (ws, req) => {
  const url    = new URL(req.url ?? '', `http://localhost`);
  const sid    = url.searchParams.get('sessionId') ?? '';
  const monIdx = parseInt(url.searchParams.get('monitor') ?? '0', 10);

  const session = registry.get(sid);
  if (!session) {
    ws.close(4404, 'Session not found');
    return;
  }

  console.log(`[ws] monitor ${monIdx} joined session ${sid}`);
  session.addSocket(ws as unknown as import('ws').WebSocket, monIdx);
});

httpServer.listen(PORT, () => {
  console.log(`multimon-rdp server → :${PORT}`);
});
