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

