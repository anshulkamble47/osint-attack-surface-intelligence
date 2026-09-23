export interface DatabaseHealth {
  connected: boolean;
  dialect: string;
  latency_ms: number;
  error: string | null;
}

export interface HealthResponse {
  status: 'ok' | 'degraded' | 'error';
  service: string;
  version: string;
  environment: string;
  timestamp: string;
  database: DatabaseHealth;
}
