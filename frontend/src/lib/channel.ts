import type { ChannelMsg, SessionInfo } from '../types';

const CHANNEL_NAME = 'multimon-rdp';
let _ch: BroadcastChannel | null = null;

export function getChannel(): BroadcastChannel {
  if (!_ch) _ch = new BroadcastChannel(CHANNEL_NAME);
  return _ch;
}

export const send = (msg: ChannelMsg) => getChannel().postMessage(msg);

export const announceSession = (session: SessionInfo)              => send({ type: 'session-announce', session });
export const requestMonitor  = (windowId: string)                  => send({ type: 'monitor-request', windowId });
export const assignMonitor   = (windowId: string, idx: number)     => send({ type: 'monitor-assign',  windowId, monitorIndex: idx });
export const endSession      = ()                                   => send({ type: 'session-end' });
