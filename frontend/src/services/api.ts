import {
  HealthResponse,
  TokenResponse,
  UserResponse,
  InvestigationResponse,
  CTDiscoveryResponse,
  AssetSummary,
  DNSReachabilityResponse,
  DNSRecordSummary,
  ServiceExposureSummary,
  IPEnrichmentResponse,
  IPAddressSummary,
  ASNSummary,
  FingerprintResponse,
  TechnologySummary,
  SecurityHeadersSummary,
  TLSMetadataSummary,
  CorrelateVulnerabilitiesResponse,
  VulnerabilityCorrelationDetail,
  GraphResponse,
  FindingResponse,
  GenerateFindingsResponse,
  FindingListResponse,
  ComparisonSummaryResponse,
  ChangeListResponse,
} from '../types/api';


const API_BASE = '/api';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(url: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    let errorDetails = `HTTP error ${response.status}`;
    try {
      const errData = await response.json();
      errorDetails = errData.detail || errData.message || errorDetails;
    } catch {
      // non-JSON error response
    }
    throw new ApiError(response.status, errorDetails);
  }

  return response.json();
}

export async function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export async function loginUser(
  username_or_email: string,
  password: string
): Promise<TokenResponse> {
  return request<TokenResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username_or_email, password }),
  });
}

export async function registerUser(
  email: string,
  username: string,
  password: string,
  full_name?: string
): Promise<UserResponse> {
  return request<UserResponse>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, username, password, full_name }),
  });
}

export async function createInvestigation(
  token: string,
  name: string,
  target_domain: string,
  organization?: string,
  description?: string
): Promise<InvestigationResponse> {
  return request<InvestigationResponse>('/investigations', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      name,
      target_domain,
      organization: organization || undefined,
      description: description || undefined,
    }),
  });
}

export async function listInvestigations(token: string): Promise<InvestigationResponse[]> {
  return request<InvestigationResponse[]>('/investigations', {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function runCTDiscovery(
  token: string,
  investigationId: string
): Promise<CTDiscoveryResponse> {
  return request<CTDiscoveryResponse>(`/investigations/${investigationId}/discover/ct`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function listInvestigationAssets(
  token: string,
  investigationId: string
): Promise<AssetSummary[]> {
  return request<AssetSummary[]>(`/investigations/${investigationId}/assets`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function resolveInvestigation(
  token: string,
  investigationId: string
): Promise<DNSReachabilityResponse> {
  return request<DNSReachabilityResponse>(`/investigations/${investigationId}/resolve`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function listInvestigationDNSRecords(
  token: string,
  investigationId: string
): Promise<DNSRecordSummary[]> {
  return request<DNSRecordSummary[]>(`/investigations/${investigationId}/dns-records`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function listInvestigationServices(
  token: string,
  investigationId: string
): Promise<ServiceExposureSummary[]> {
  return request<ServiceExposureSummary[]>(`/investigations/${investigationId}/services`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function enrichInvestigationIPs(
  token: string,
  investigationId: string
): Promise<IPEnrichmentResponse> {
  return request<IPEnrichmentResponse>(`/investigations/${investigationId}/enrich/ip`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function listInvestigationIPAddresses(
  token: string,
  investigationId: string
): Promise<IPAddressSummary[]> {
  return request<IPAddressSummary[]>(`/investigations/${investigationId}/ip-addresses`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function listInvestigationASNs(
  token: string,
  investigationId: string
): Promise<ASNSummary[]> {
  return request<ASNSummary[]>(`/investigations/${investigationId}/asns`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function runFingerprinting(
  token: string,
  investigationId: string
): Promise<FingerprintResponse> {
  return request<FingerprintResponse>(`/investigations/${investigationId}/fingerprint`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function listInvestigationTechnologies(
  token: string,
  investigationId: string,
  scanRunId?: string
): Promise<TechnologySummary[]> {
  const query = scanRunId ? `?scan_run_id=${scanRunId}` : '';
  return request<TechnologySummary[]>(`/investigations/${investigationId}/technologies${query}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function listInvestigationSecurityHeaders(
  token: string,
  investigationId: string,
  scanRunId?: string
): Promise<SecurityHeadersSummary[]> {
  const query = scanRunId ? `?scan_run_id=${scanRunId}` : '';
  return request<SecurityHeadersSummary[]>(`/investigations/${investigationId}/security-headers${query}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function listInvestigationTLSMetadata(
  token: string,
  investigationId: string,
  scanRunId?: string
): Promise<TLSMetadataSummary[]> {
  const query = scanRunId ? `?scan_run_id=${scanRunId}` : '';
  return request<TLSMetadataSummary[]>(`/investigations/${investigationId}/tls-metadata${query}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function correlateInvestigationVulnerabilities(
  token: string,
  investigationId: string
): Promise<CorrelateVulnerabilitiesResponse> {
  return request<CorrelateVulnerabilitiesResponse>(`/investigations/${investigationId}/vulnerabilities/correlate`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function listInvestigationVulnerabilities(
  token: string,
  investigationId: string,
  scanRunId?: string,
  isKev?: boolean,
  verificationStatus?: string
): Promise<VulnerabilityCorrelationDetail[]> {
  const params = new URLSearchParams();
  if (scanRunId) params.append('scan_run_id', scanRunId);
  if (isKev !== undefined) params.append('is_kev', String(isKev));
  if (verificationStatus) params.append('verification_status', verificationStatus);
  const qs = params.toString() ? `?${params.toString()}` : '';
  return request<VulnerabilityCorrelationDetail[]>(`/investigations/${investigationId}/vulnerabilities${qs}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function getInvestigationGraph(
  token: string,
  investigationId: string,
  scanRunId?: string,
  nodeTypes?: string[],
  relationshipTypes?: string[]
): Promise<GraphResponse> {
  const params = new URLSearchParams();
  if (scanRunId) params.append('scan_run_id', scanRunId);
  if (nodeTypes && nodeTypes.length > 0) {
    nodeTypes.forEach(nt => params.append('node_type', nt));
  }
  if (relationshipTypes && relationshipTypes.length > 0) {
    relationshipTypes.forEach(rt => params.append('relationship_type', rt));
  }
  const qs = params.toString() ? `?${params.toString()}` : '';
  return request<GraphResponse>(`/investigations/${investigationId}/graph${qs}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function generateInvestigationFindings(
  token: string,
  investigationId: string,
  scanRunId?: string
): Promise<GenerateFindingsResponse> {
  const qs = scanRunId ? `?scan_run_id=${scanRunId}` : '';
  return request<GenerateFindingsResponse>(`/investigations/${investigationId}/findings/generate${qs}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function listInvestigationFindings(
  token: string,
  investigationId: string,
  scanRunId?: string,
  severity?: string,
  status?: string,
  findingType?: string,
  category?: string
): Promise<FindingListResponse> {
  const params = new URLSearchParams();
  if (scanRunId) params.append('scan_run_id', scanRunId);
  if (severity) params.append('severity', severity);
  if (status) params.append('status', status);
  if (findingType) params.append('finding_type', findingType);
  if (category) params.append('category', category);
  const qs = params.toString() ? `?${params.toString()}` : '';
  return request<FindingListResponse>(`/investigations/${investigationId}/findings${qs}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function getInvestigationFindingDetail(
  token: string,
  investigationId: string,
  findingId: string
): Promise<FindingResponse> {
  return request<FindingResponse>(`/investigations/${investigationId}/findings/${findingId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function updateInvestigationFindingStatus(
  token: string,
  investigationId: string,
  findingId: string,
  status: string
): Promise<FindingResponse> {
  return request<FindingResponse>(`/investigations/${investigationId}/findings/${findingId}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({ status }),
  });
}

export async function compareScanRuns(
  token: string,
  investigationId: string,
  baselineScanRunId?: string,
  currentScanRunId?: string
): Promise<ComparisonSummaryResponse> {
  return request<ComparisonSummaryResponse>(`/investigations/${investigationId}/monitoring/compare`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      baseline_scan_run_id: baselineScanRunId || null,
      current_scan_run_id: currentScanRunId || null,
    }),
  });
}

export async function listInvestigationChanges(
  token: string,
  investigationId: string,
  baselineScanRunId?: string,
  currentScanRunId?: string,
  changeType?: string,
  category?: string,
  assetId?: string
): Promise<ChangeListResponse> {
  const params = new URLSearchParams();
  if (baselineScanRunId) params.append('baseline_scan_run_id', baselineScanRunId);
  if (currentScanRunId) params.append('current_scan_run_id', currentScanRunId);
  if (changeType) params.append('change_type', changeType);
  if (category) params.append('category', category);
  if (assetId) params.append('asset_id', assetId);
  const qs = params.toString() ? `?${params.toString()}` : '';
  return request<ChangeListResponse>(`/investigations/${investigationId}/changes${qs}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function getMonitoringSummary(
  token: string,
  investigationId: string
): Promise<ChangeListResponse> {
  return request<ChangeListResponse>(`/investigations/${investigationId}/monitoring/summary`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}





