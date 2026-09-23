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

export interface DNSRecordSummary {
  id: string;
  subdomain_id: string;
  record_type: string;
  value: string;
  ttl?: number | null;
  resolver: string;
  collected_at: string;
  scan_run_id?: string | null;
}

export interface ServiceExposureSummary {
  id: string;
  asset_id: string;
  port: number;
  protocol: string;
  service_name: string;
  http_status?: number | null;
  page_title?: string | null;
  observed_at: string;
  scan_run_id?: string | null;
}

export interface CandidateResolutionDetail {
  hostname: string;
  is_resolving: boolean;
  is_reachable: boolean;
  dns_records_count: number;
  services_count: number;
  dns_records: DNSRecordSummary[];
  service_exposures: ServiceExposureSummary[];
  error?: string | null;
}

export interface DNSReachabilityResponse {
  investigation_id: string;
  scan_run_id: string;
  target_domain: string;
  candidates_processed: number;
  resolved: number;
  not_resolved: number;
  reachable: number;
  unreachable: number;
  dns_records_discovered: number;
  services_discovered: number;
  results: CandidateResolutionDetail[];
  completed_at: string;
  note: string;
}

