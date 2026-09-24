import createClient from 'openapi-fetch';
import type { paths } from './schema';
import { getApiKey, notifyUnauthorized } from './auth';

export class ApiError extends Error {
  status: number;
  retryAfter?: number;

  constructor(status: number, message: string, retryAfter?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

export const rawClient = createClient<paths>({
  baseUrl: typeof window !== 'undefined' && window.location?.origin && !window.location.origin.includes('null')
    ? `${window.location.origin.replace(/\/$/, '')}/api`
    : '/api',
  fetch: (req: Request) => fetch(req),
});

// Middleware to inject X-API-Key and handle 401
rawClient.use({
  async onRequest({ request }) {
    const key = getApiKey();
    if (key) {
      request.headers.set('X-API-Key', key);
    }
    return request;
  },
  async onResponse({ response }) {
    if (response.status === 401) {
      notifyUnauthorized();
    }
    return response;
  },
});

export function sanitizeErrorMessage(status: number, rawData: unknown): string {
  if (typeof rawData === 'string') {
    return rawData;
  }
  if (rawData && typeof rawData === 'object') {
    const obj = rawData as Record<string, unknown>;
    if (typeof obj.detail === 'string') {
      return obj.detail;
    }
    if (Array.isArray(obj.detail)) {
      // Pydantic validation error format
      return obj.detail
        .map((d: Record<string, unknown>) => {
          const loc = Array.isArray(d.loc) ? d.loc.join('.') : '';
          const msg = typeof d.msg === 'string' ? d.msg : 'Invalid field';
          return loc ? `${loc}: ${msg}` : msg;
        })
        .join(', ');
    }
    if (typeof obj.message === 'string') {
      return obj.message;
    }
  }

  switch (status) {
    case 400:
      return 'Invalid request parameters or target scope rejected.';
    case 401:
      return 'Authentication required. Invalid or missing API key.';
    case 403:
      return 'Access forbidden by security policy.';
    case 404:
      return 'The requested resource was not found.';
    case 409:
      return 'Conflict: A scan is already running on this target host.';
    case 422:
      return 'Request validation failed.';
    case 429:
      return 'Maximum concurrent scan limit reached. Please retry shortly.';
    case 500:
      return 'Internal server error occurred.';
    default:
      return `HTTP error ${status}`;
  }
}

export default rawClient;
