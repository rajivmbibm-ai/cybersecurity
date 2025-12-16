export interface LogEntry {
  id: string;
  timestamp: string;
  message: string;
  type: 'info' | 'error' | 'success' | 'warning';
}

export enum AuthStatus {
  IDLE = 'IDLE',
  AUTHENTICATING = 'AUTHENTICATING',
  SUCCESS = 'SUCCESS',
  LOCKED = 'LOCKED'
}