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

export interface UserResponse {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in_seconds: number;
  user: UserResponse;
}

export interface InvestigationResponse {
  id: string;
  reference_code: string;
  target_id: string;
  target_domain: string;
  title: string;
  status: string;
  scan_options: Record<string, any>;
  created_by_id: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface CertificateSummary {
  fingerprint_sha256: string;
  subject_cn: string;
  issuer: string;
  san_list: string[];
  valid_from: string;
  valid_to: string;
  is_expired: boolean;
  ct_log_id?: string | null;
}

export interface CTDiscoveryResponse {
  investigation_id: string;
  target_domain: string;
  scan_run_id: string;
  source: string;
  hostname_count: number;
  certificate_count: number;
  hostnames: string[];
  certificates: CertificateSummary[];
  discovery_timestamp: string;
  note: string;
}

export interface AssetSummary {
  id: string;
  asset_type: string;
  value: string;
  is_active: boolean;
  confidence: number;
  source: string;
  risk_score: number;
  tags: string[];
  first_seen_at: string;
  last_seen_at: string;
}
