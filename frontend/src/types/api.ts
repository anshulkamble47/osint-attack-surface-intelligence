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

export interface ASNSummary {
  id?: string | null;
  asn_number: number;
  name: string;
  country?: string | null;
  allocated_prefix?: string | null;
  ip_count?: number | null;
}

export interface RDAPSummary {
  network_name?: string | null;
  handle?: string | null;
  start_address?: string | null;
  end_address?: string | null;
  cidr?: string | null;
  country?: string | null;
  organization?: string | null;
  status: string[];
  registration_date?: string | null;
  last_changed_date?: string | null;
}

export interface IPAddressSummary {
  id: string;
  asset_id: string;
  ip_address: string;
  ip_version: number;
  reverse_dns?: string | null;
  asn_id?: string | null;
  asn?: ASNSummary | null;
  country?: string | null;
  region?: string | null;
  organization?: string | null;
  is_active: boolean;
  last_scan_run_id?: string | null;
}

export interface IPEnrichmentDetail {
  ip_address: string;
  ip_version: number;
  is_public: boolean;
  status: string;
  asn?: ASNSummary | null;
  rdap?: RDAPSummary | null;
  error?: string | null;
}

export interface IPEnrichmentResponse {
  investigation_id: string;
  scan_run_id: string;
  target_domain: string;
  ips_processed: number;
  public_ips: number;
  skipped_non_public: number;
  asn_success: number;
  rdap_success: number;
  failed: number;
  results: IPEnrichmentDetail[];
  completed_at: string;
  note: string;
}

export interface TechnologySummary {
  id: string;
  asset_id: string;
  asset_value?: string | null;
  service_id?: string | null;
  scan_run_id?: string | null;
  name: string;
  version?: string | null;
  cpe?: string | null;
  category: string;
  confidence: number;
  evidence_source: string;
  detected_at: string;
}

export interface SecurityHeaderDetail {
  header_name: string;
  present: boolean;
  value?: string | null;
  status: string;
  interpretation: string;
}

export interface SecurityHeadersSummary {
  service_id: string;
  asset_id: string;
  asset_value: string;
  url: string;
  port: number;
  protocol: string;
  service_name: string;
  http_status?: number | null;
  headers: Record<string, SecurityHeaderDetail>;
  scan_run_id?: string | null;
  observed_at: string;
}

export interface TLSMetadataSummary {
  service_id: string;
  asset_id: string;
  asset_value: string;
  url: string;
  tls_version?: string | null;
  cipher_suite?: string | null;
  cert_subject?: string | null;
  cert_issuer?: string | null;
  cert_valid_from?: string | null;
  cert_valid_to?: string | null;
  cert_san_list: string[];
  scan_run_id?: string | null;
  observed_at: string;
}

export interface ServiceFingerprintDetail {
  service_id: string;
  asset_id: string;
  hostname: string;
  url: string;
  port: number;
  service_name: string;
  is_reachable: boolean;
  status_code?: number | null;
  page_title?: string | null;
  technologies_count: number;
  technologies: TechnologySummary[];
  security_headers?: SecurityHeadersSummary | null;
  tls_metadata?: TLSMetadataSummary | null;
  error?: string | null;
}

export interface FingerprintResponse {
  investigation_id: string;
  scan_run_id: string;
  target_domain: string;
  services_processed: number;
  reachable: number;
  technologies_detected: number;
  security_headers_analyzed: number;
  tls_observations: number;
  results: ServiceFingerprintDetail[];
  completed_at: string;
  note: string;
}

export interface KEVDetail {
  vendor_project: string;
  product: string;
  vulnerability_name: string;
  date_added?: string | null;
  required_action: string;
  due_date?: string | null;
  ransomware_campaign: string;
}

export interface VulnerabilityCorrelationDetail {
  id: string;
  technology_id: string;
  technology_name: string;
  observed_version?: string | null;
  asset_id: string;
  asset_value?: string | null;
  cve_id: string;
  title?: string | null;
  description: string;
  severity: string;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  is_kev: boolean;
  kev_details?: KEVDetail | null;
  correlation_status: string;
  match_confidence: number;
  match_basis: string;
  source: string;
  published_date?: string | null;
  scan_run_id?: string | null;
  created_at: string;
}

export interface CorrelateVulnerabilitiesResponse {
  investigation_id: string;
  scan_run_id: string;
  target_domain: string;
  technologies_analyzed: number;
  cves_correlated: number;
  potential_matches: number;
  kev_listed_cves: number;
  requires_verification: number;
  results: VulnerabilityCorrelationDetail[];
  completed_at: string;
  note: string;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  asset_id?: string | null;
  entity_id?: string | null;
  metadata: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  scan_run_id?: string | null;
  evidence_id?: string | null;
  confidence: number;
  attributes: Record<string, any>;
}

export interface GraphStatistics {
  node_count: number;
  edge_count: number;
  nodes_by_type: Record<string, number>;
  edges_by_type: Record<string, number>;
}

export interface GraphResponse {
  investigation_id: string;
  scan_run_id?: string | null;
  scan_run_number?: number | null;
  target_domain: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  statistics: GraphStatistics;
}

export interface FindingAssetSummary {
  id: string;
  asset_type: string;
  value: string;
}

export interface FindingTechnologySummary {
  id: string;
  name: string;
  version?: string | null;
  cpe?: string | null;
  category: string;
  confidence: number;
}

export interface FindingVulnerabilitySummary {
  id: string;
  cve_id: string;
  title?: string | null;
  severity: string;
  cvss_v3_score?: number | null;
  cvss_vector?: string | null;
  source: string;
}

export interface FindingEvidenceSummary {
  id: string;
  reference_code: string;
  evidence_type: string;
  source: string;
  sha256_hash: string;
  collected_at: string;
}

export interface FindingResponse {
  id: string;
  reference_code: string;
  investigation_id: string;
  scan_run_id?: string | null;
  asset_id: string;
  technology_id?: string | null;
  vulnerability_id?: string | null;
  title: string;
  description: string;
  category: string;
  finding_type: string;
  severity: string;
  status: string;
  context_score: number;
  risk_score: number;
  risk_category: string;
  cvss_score?: number | null;
  is_kev: boolean;
  score_breakdown: Record<string, any>;
  risk_factors: Record<string, any>;
  remediation?: string | null;
  recommendation: string;
  is_verified: boolean;
  asset?: FindingAssetSummary | null;
  technology?: FindingTechnologySummary | null;
  vulnerability?: FindingVulnerabilitySummary | null;
  evidence_items: FindingEvidenceSummary[];
  created_at: string;
  updated_at?: string | null;
}

export interface GenerateFindingsResponse {
  investigation_id: string;
  scan_run_id?: string | null;
  scan_run_number?: number | null;
  findings_generated: number;
  findings_updated: number;
  findings_total: number;
  severity_breakdown: Record<string, number>;
  risk_category_breakdown: Record<string, number>;
  findings: FindingResponse[];
  completed_at: string;
  note: string;
}

export interface FindingListResponse {
  investigation_id: string;
  scan_run_id?: string | null;
  total: number;
  severity_breakdown: Record<string, number>;
  risk_category_breakdown: Record<string, number>;
  findings: FindingResponse[];
}

export interface ChangeRecordResponse {
  id: string;
  investigation_id: string;
  baseline_scan_run_id?: string | null;
  current_scan_run_id: string;
  asset_id?: string | null;
  asset_value?: string | null;
  change_type: 'ADDED' | 'REMOVED' | 'MODIFIED';
  field_name: string;
  category: string;
  entity_key?: string | null;
  description?: string | null;
  old_value?: Record<string, any> | null;
  new_value?: Record<string, any> | null;
  evidence_id?: string | null;
  evidence_hash?: string | null;
  detected_at: string;
}

export interface CompareScanRunsRequest {
  baseline_scan_run_id?: string | null;
  current_scan_run_id?: string | null;
}

export interface ComparisonSummaryResponse {
  investigation_id: string;
  baseline_scan_run_id?: string | null;
  current_scan_run_id: string;
  baseline_scan_run_number?: number | null;
  current_scan_run_number?: number | null;
  total_changes: number;
  added_count: number;
  removed_count: number;
  modified_count: number;
  changes_by_category: Record<string, number>;
  changes_by_type: Record<string, number>;
  changes: ChangeRecordResponse[];
  compared_at: string;
  message: string;
}

export interface ChangeListResponse {
  investigation_id: string;
  baseline_scan_run_id?: string | null;
  current_scan_run_id?: string | null;
  total: number;
  added_count: number;
  removed_count: number;
  modified_count: number;
  changes_by_category: Record<string, number>;
  changes: ChangeRecordResponse[];
}





