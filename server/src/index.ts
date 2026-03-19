import * as http from 'http';
import * as crypto from 'crypto';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const GuacamoleLite = require('guacamole-lite') as new (
  wsOptions: unknown, guacdOptions: unknown, clientOptions: unknown
) => void;

const GUACD_HOST = process.env.GUACD_HOST ?? 'localhost';
const GUACD_PORT = parseInt(process.env.GUACD_PORT ?? '4822', 10);
const PORT       = parseInt(process.env.PORT ?? '3001', 10);

const KEY = Buffer.from(
  (process.env.ENCRYPTION_KEY ?? 'multimon-rdp-default-key-32byte').slice(0, 32).padEnd(32, '0'),
);

// ── Types ─────────────────────────────────────────────────────────────────────

interface ConnectBody {
  protocol:  'rdp' | 'vnc';
  host:      string;
  port?:     number;
  username?: string;
  password?: string;
  domain?:   string;
  // Display
  monitors:      number;   // 1 – 3
  monitorWidth:  number;
  monitorHeight: number;
  colorDepth?:   number;
  // RDP options
  security?:    string;
  ignoreCert?:  boolean;
  // VNC options
  viewOnly?: boolean;
}

// ── Token generation ─────────────────────────────────────────────────────────

function makeToken(p: ConnectBody): string {
  const monitors = Math.min(Math.max(p.monitors, 1), 3);
  const w        = p.monitorWidth  || 1920;
  const h        = p.monitorHeight || 1080;

  let settings: Record<string, string>;

  if (p.protocol === 'rdp') {
    settings = {
      hostname:              p.host,
      port:                  String(p.port ?? 3389),
      username:              p.username ?? '',
      password:              p.password ?? '',
      domain:                p.domain   ?? '',
      // Combined width spans all monitors; height is per-monitor
      width:                 String(w * monitors),
      height:                String(h),
      dpi:                   '96',
      'color-depth':         String(p.colorDepth ?? 24),
      security:              p.security  ?? 'any',
      'ignore-cert':         (p.ignoreCert !== false) ? 'true' : 'false',
      'disable-audio':       'true',
      'enable-wallpaper':    'true',
      'enable-theming':      'true',
      'enable-font-smoothing': 'true',
      'resize-method':       'reconnect',
    };
    // Multi-monitor: tell FreeRDP to present N monitors to Windows
    if (monitors > 1) {
      settings['multi-monitor']  = 'true';
      settings['normalize-clip'] = 'true';
    }
  } else {
    // VNC — single monitor per connection
    settings = {
      hostname:   p.host,
      port:       String(p.port ?? 5900),
      password:   p.password ?? '',
      width:      String(w),
      height:     String(h),
      'color-depth': String(p.colorDepth ?? 24),
      'view-only': p.viewOnly ? 'true' : 'false',
    };
  }

  const payload = { connection: { type: p.protocol, settings } };
  const iv      = crypto.randomBytes(16);
  const cipher  = crypto.createCipheriv('aes-256-cbc', KEY, iv);
  const enc     = cipher.update(JSON.stringify(payload), 'utf8', 'base64') + cipher.final('base64');
  return Buffer.from(JSON.stringify({ iv: iv.toString('base64'), value: enc })).toString('base64');
}

// ── HTTP server ───────────────────────────────────────────────────────────────

const httpServer = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (req.method === 'POST' && req.url === '/api/connect') {
    let body = '';
    req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const params = JSON.parse(body) as ConnectBody;
        if (!params.host)     { res.writeHead(400); res.end(JSON.stringify({ error: 'Missing host' })); return; }
        if (!params.protocol) { res.writeHead(400); res.end(JSON.stringify({ error: 'Missing protocol' })); return; }

        const monitors     = Math.min(Math.max(params.monitors || 1, 1), 3);
        const monitorWidth  = params.monitorWidth  || 1920;
        const monitorHeight = params.monitorHeight || 1080;
        const token = makeToken({ ...params, monitors, monitorWidth, monitorHeight });

        console.log(`[connect] ${params.protocol} → ${params.username ?? ''}@${params.host} | ${monitors} monitor(s) @ ${monitorWidth}x${monitorHeight}`);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token, monitors, monitorWidth, monitorHeight }));
      } catch {
        res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, guacd: `${GUACD_HOST}:${GUACD_PORT}` }));
    return;
  }

  res.writeHead(404); res.end();
});

// ── GuacamoleLite WebSocket bridge ────────────────────────────────────────────

new GuacamoleLite(
  { server: httpServer, path: '/ws' },
  { host: GUACD_HOST, port: GUACD_PORT },
  {
    crypt: { cypher: 'AES-256-CBC', key: KEY.toString() },
    log:   { level: 'ERRORS' },
  },
);

httpServer.listen(PORT, () => {
  console.log(`multimon-rdp server → :${PORT}`);
  console.log(`guacd               → ${GUACD_HOST}:${GUACD_PORT}`);
});
