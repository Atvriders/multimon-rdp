import Guacamole from 'guacamole-common-js';
import { sendGuacData } from './channel';

/**
 * WebSocket tunnel to guacamole-lite. Intercepts raw Guacamole instructions
 * and broadcasts them via BroadcastChannel so secondary monitor windows can
 * render the same session without a second WebSocket connection.
 */
export class RDPTunnel extends Guacamole.WebSocketTunnel {
  constructor(url: string, token: string) {
    const wsUrl = url.replace(/^http/, 'ws').replace(/\/$/, '') + '/ws?token=' + encodeURIComponent(token);
    super(wsUrl);
  }

  // Called by guacamole-common-js for every instruction received.
  // We hook here to forward raw data to secondary windows.
  override receiveData(data: string): void {
    sendGuacData(data);
    super.receiveData(data);
  }
}

/**
 * Fake tunnel for secondary monitor windows. Receives Guacamole instructions
 * forwarded via BroadcastChannel from the primary window's RDPTunnel and
 * feeds them to a Guacamole.Client as if they came from a WebSocket.
 */
export class BroadcastTunnel extends Guacamole.Tunnel {
  constructor() {
    super();
  }

  receiveData(raw: string): void {
    // Parse the raw Guacamole instruction string and dispatch oninstruction.
    // Format: length.opcode,length.arg1,...; (semicolon-terminated)
    let idx = 0;
    while (idx < raw.length) {
      const semi = raw.indexOf(';', idx);
      if (semi === -1) break;
      const instruction = raw.slice(idx, semi + 1);
      idx = semi + 1;

      const elements: string[] = [];
      let pos = 0;
      while (pos < instruction.length && instruction[pos] !== ';') {
        const dot = instruction.indexOf('.', pos);
        if (dot === -1) break;
        const len = parseInt(instruction.slice(pos, dot), 10);
        if (isNaN(len)) break;
        elements.push(instruction.slice(dot + 1, dot + 1 + len));
        pos = dot + 1 + len;
        if (instruction[pos] === ',') pos++;
      }
      if (elements.length > 0) {
        this.oninstruction?.(elements[0], elements.slice(1));
      }
    }
  }

  override connect(_data: string): void {
    this.setState(Guacamole.Tunnel.State.OPEN);
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  override sendMessage(..._elements: unknown[]): void {
    // Secondary windows send input back via BroadcastChannel, not WebSocket
  }

  override disconnect(): void {
    this.setState(Guacamole.Tunnel.State.CLOSED);
  }
}
