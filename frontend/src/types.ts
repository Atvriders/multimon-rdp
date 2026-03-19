export type Protocol = 'rdp';

export interface ConnectParams {
  host:          string;
  port:          number;
  username:      string;
  password:      string;
  domain:        string;
  monitorWidth:  number;
  monitorHeight: number;
  ignoreCert:    boolean;
}

export interface SessionInfo {
  sessionId:     string;
  monitors:      number;
  monitorWidth:  number;
  monitorHeight: number;
}

export type ChannelMsg =
  | { type: 'session-announce'; session: SessionInfo }
  | { type: 'monitor-request'; windowId: string }
  | { type: 'monitor-assign';  windowId: string; monitorIndex: number }
  | { type: 'key';   scancode: number; pressed: boolean }
  | { type: 'session-end' };
