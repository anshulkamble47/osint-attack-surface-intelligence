import { HealthResponse } from '../types/api';

const API_BASE = '/api';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE}/health`, {
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    let errorDetails = `HTTP error ${response.status}`;
    try {
      const errData = await response.json();
      errorDetails = errData.message || errorDetails;
    } catch {
      // ignore json parse error on non-json error responses
    }
    throw new ApiError(response.status, errorDetails);
  }

  return response.json();
}
