import { EventEmitter } from "events";

export interface WsProgressEvent {
  type: "progress";
  message: string;
  percent?: number;
}

export interface WsFindingEvent {
  type: "finding";
  finding: Record<string, unknown>;
}

export interface WsCompleteEvent {
  type: "complete";
  scan_id: string;
}

export interface WsErrorEvent {
  type: "error";
  message: string;
}

export type WsEvent =
  | WsProgressEvent
  | WsFindingEvent
  | WsCompleteEvent
  | WsErrorEvent;

type WsEventMap = {
  finding: [WsFindingEvent];
  progress: [WsProgressEvent];
  complete: [WsCompleteEvent];
  error: [WsErrorEvent];
  connected: [];
  disconnected: [];
};

export class AegisWsClient extends EventEmitter {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectDelay = 2000;
  private maxReconnectDelay = 30000;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionalClose = false;
  private currentDelay: number;

  constructor(url: string) {
    super();
    this.url = url;
    this.currentDelay = this.reconnectDelay;
  }

  connect(): void {
    this.intentionalClose = false;
    this._connect();
  }

  private _connect(): void {
    if (this.ws) {
      this.ws.close();
    }

    try {
      this.ws = new WebSocket(this.url);
    } catch (err) {
      this.emit("error", { type: "error", message: `WebSocket connection failed: ${err}` });
      this._scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.currentDelay = this.reconnectDelay;
      this.emit("connected");
    };

    this.ws.onmessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(String(event.data)) as WsEvent;
        switch (data.type) {
          case "finding":
            this.emit("finding", data);
            break;
          case "progress":
            this.emit("progress", data);
            break;
          case "complete":
            this.emit("complete", data);
            break;
          case "error":
            this.emit("error", data);
            break;
        }
      } catch {
        // Ignore malformed messages
      }
    };

    this.ws.onerror = () => {
      this.emit("error", {
        type: "error",
        message: "WebSocket error",
      } as WsErrorEvent);
    };

    this.ws.onclose = () => {
      this.emit("disconnected");
      if (!this.intentionalClose) {
        this._scheduleReconnect();
      }
    };
  }

  private _scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    this.reconnectTimer = setTimeout(() => {
      if (!this.intentionalClose) {
        this._connect();
      }
    }, this.currentDelay);
    this.currentDelay = Math.min(
      this.currentDelay * 2,
      this.maxReconnectDelay
    );
  }

  send(data: Record<string, unknown>): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  disconnect(): void {
    this.intentionalClose = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  get connected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  // TypeScript typed overloads for event emitter
  override on<K extends keyof WsEventMap>(
    event: K,
    listener: (...args: WsEventMap[K]) => void
  ): this {
    return super.on(event, listener as (...args: unknown[]) => void);
  }

  override off<K extends keyof WsEventMap>(
    event: K,
    listener: (...args: WsEventMap[K]) => void
  ): this {
    return super.off(event, listener as (...args: unknown[]) => void);
  }

  override emit<K extends keyof WsEventMap>(
    event: K,
    ...args: WsEventMap[K]
  ): boolean {
    return super.emit(event, ...args);
  }
}
