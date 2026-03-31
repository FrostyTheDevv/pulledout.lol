import { io, Socket } from 'socket.io-client';
import { getFingerprint } from './security';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:5000';

export interface ScanProgress {
  scan_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  stage: string;
  findings_count: number;
  eta_seconds?: number;
}

export interface ScanFinding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  title: string;
  description: string;
  url?: string;
  remediation?: string;
}

type EventCallback = (...args: any[]) => void;

class WebSocketClient {
  private socket: Socket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 1000;
  private listeners: Map<string, Set<EventCallback>> = new Map();
  
  constructor() {
    this.connect();
  }
  
  private async connect() {
    try {
      const fingerprint = await getFingerprint();
      
      this.socket = io(WS_URL, {
        transports: ['websocket', 'polling'],
        auth: {
          fingerprint,
        },
        reconnection: true,
        reconnectionAttempts: this.maxReconnectAttempts,
        reconnectionDelay: this.reconnectDelay,
        reconnectionDelayMax: 5000,
      });
      
      this.setupEventHandlers();
      
    } catch (error) {
      console.error('WebSocket connection failed:', error);
      this.scheduleReconnect();
    }
  }
  
  private setupEventHandlers() {
    if (!this.socket) return;
    
    this.socket.on('connect', () => {
      console.log('WebSocket connected');
      this.reconnectAttempts = 0;
      this.emit('connection', true);
    });
    
    this.socket.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason);
      this.emit('connection', false);
      
      if (reason === 'io server disconnect') {
        // Server disconnected, need manual reconnection
        this.scheduleReconnect();
      }
    });
    
    this.socket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
      this.scheduleReconnect();
    });
    
    // Scan events
    this.socket.on('scan:started', (data) => {
      this.emit('scan:started', data);
    });
    
    this.socket.on('scan:progress', (data: ScanProgress) => {
      this.emit('scan:progress', data);
    });
    
    this.socket.on('scan:finding', (data: ScanFinding) => {
      this.emit('scan:finding', data);
    });
    
    this.socket.on('scan:completed', (data) => {
      this.emit('scan:completed', data);
    });
    
    this.socket.on('scan:failed', (data) => {
      this.emit('scan:failed', data);
    });
    
    // System events
    this.socket.on('system:alert', (data) => {
      this.emit('system:alert', data);
    });
  }
  
  private scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      this.emit('connection:failed');
      return;
    }
    
    this.reconnectAttempts++;
    const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts), 30000);
    
    console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
    
    setTimeout(() => {
      this.connect();
    }, delay);
  }
  
  // Event management
  on(event: string, callback: EventCallback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);
    
    // Also register with socket if connected
    if (this.socket) {
      this.socket.on(event, callback);
    }
  }
  
  off(event: string, callback?: EventCallback) {
    if (callback) {
      this.listeners.get(event)?.delete(callback);
      if (this.socket) {
        this.socket.off(event, callback);
      }
    } else {
      this.listeners.delete(event);
      if (this.socket) {
        this.socket.off(event);
      }
    }
  }
  
  private emit(event: string, ...args: any[]) {
    this.listeners.get(event)?.forEach(callback => {
      try {
        callback(...args);
      } catch (error) {
        console.error(`Error in ${event} listener:`, error);
      }
    });
  }
  
  // Public methods
  subscribeScan(scanId: string) {
    if (this.socket) {
      this.socket.emit('scan:subscribe', { scan_id: scanId });
    }
  }
  
  unsubscribeScan(scanId: string) {
    if (this.socket) {
      this.socket.emit('scan:unsubscribe', { scan_id: scanId });
    }
  }
  
  send(event: string, data: any) {
    if (this.socket && this.socket.connected) {
      this.socket.emit(event, data);
    } else {
      console.warn('WebSocket not connected, queuing message');
      // Could implement message queue here
    }
  }
  
  isConnected(): boolean {
    return this.socket?.connected || false;
  }
  
  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.listeners.clear();
  }
}

// Export singleton instance
export const wsClient = new WebSocketClient();
export default wsClient;
