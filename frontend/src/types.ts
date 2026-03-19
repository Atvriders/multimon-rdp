export type Protocol = 'rdp' | 'vnc';

export interface ConnectParams {
  protocol:  Protocol;
  host:      string;
  port:      number;
  username:  string;
  password:  string;
  domain:    string;
  monitors:  number;   // 1 – 3
  monitorWidth:  number;
  monitorHeight: number;
  colorDepth: number;
  // RDP
  security:   string;
  ignoreCert: boolean;
  // VNC
  viewOnly: boolean;
}

export interface SessionInfo {
  token:         string;
  monitors:      number;
  monitorWidth:  number;
  monitorHeight: number;
}

// BroadcastChannel messages
export type ChannelMsg =
  | { type: 'session-announce'; session: SessionInfo }
  | { type: 'monitor-request'; windowId: string }
  | { type: 'monitor-assign';  windowId: string; monitorIndex: number }
  | { type: 'guac-data';  data: string }
  | { type: 'mouse'; x: number; y: number; buttons: number; up: boolean; down: boolean }
  | { type: 'key';   keysym: number; pressed: boolean }
  | { type: 'session-end' };
