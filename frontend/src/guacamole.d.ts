declare module 'guacamole-common-js' {
  namespace Guacamole {
    class Tunnel {
      oninstruction: ((opcode: string, args: string[]) => void) | null;
      connect(data: string): void;
      sendMessage(...elements: unknown[]): void;
      disconnect(): void;
      setState(state: number): void;
    }
    namespace Tunnel {
      const State: { OPEN: number; CLOSED: number; CONNECTING: number; UNSTABLE: number };
    }

    class WebSocketTunnel extends Tunnel {
      constructor(url: string);
      receiveData(data: string): void;
    }

    class Client {
      constructor(tunnel: Tunnel);
      getDisplay(): Display;
      connect(data: string): void;
      disconnect(): void;
      sendMouseState(state: Mouse.State): void;
      sendKeyEvent(pressed: number, keysym: number): void;
      onerror:       ((error: unknown) => void) | null;
      onstatechange: ((state: number) => void) | null;
    }

    class Display {
      getElement(): HTMLElement;
      getHeight(): number;
      getWidth(): number;
      scale(scale: number): void;
      onresize: (() => void) | null;
    }

    namespace Mouse {
      class State {
        constructor(
          x: number, y: number,
          left: boolean, middle: boolean, right: boolean,
          up: boolean, down: boolean,
        );
      }
    }

    class Keyboard {
      constructor(element: Document | HTMLElement);
      onkeydown: ((keysym: number) => void) | null;
      onkeyup:   ((keysym: number) => void) | null;
    }
  }

  export = Guacamole;
}
