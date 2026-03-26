import type { AuthBaseOptions } from './types';
import {
  normalizeUcanCapabilities,
  normalizeUcanCapability,
  type UcanCapability,
} from './ucan';

export type CentralAuthBaseOptions = AuthBaseOptions & {
  baseUrl?: string;
  issuerPath?: string;
  sessionPath?: string;
  issuePath?: string;
  storeSessionToken?: boolean;
  sessionTokenStorageKey?: string;
};

export type CentralIssuerInfo = {
  enabled?: boolean;
  issuerDid?: string;
  defaultAudience?: string;
  defaultCapabilities?: UcanCapability[];
  response: unknown;
};

export type CreateCentralSessionOptions = CentralAuthBaseOptions & {
  subject: string;
  sessionTtlMs?: number;
};

export type CentralSessionResult = {
  subject: string;
  sessionToken: string;
  expiresAt?: number;
  issuerDid?: string;
  response: unknown;
};

export type IssueCentralUcanOptions = CentralAuthBaseOptions & {
  sessionToken?: string | null;
  audience?: string;
  capabilities?: UcanCapability[];
  expiresInMs?: number;
  ttlMs?: number;
};

export type CentralUcanIssueResult = {
  ucan: string;
  issuerDid?: string;
  subject?: string;
  audience?: string;
  capabilities?: UcanCapability[];
  exp?: number;
  nbf?: number;
  iat?: number;
  response: unknown;
};

export type CreateAndIssueCentralUcanOptions = CentralAuthBaseOptions & {
  subject: string;
  sessionTtlMs?: number;
  audience?: string;
  capabilities?: UcanCapability[];
  expiresInMs?: number;
  ttlMs?: number;
};

export type CreateAndIssueCentralUcanResult = {
  session: CentralSessionResult;
  issue: CentralUcanIssueResult;
};

export type AuthCentralUcanFetchOptions = CentralAuthBaseOptions & {
  ucan?: string | null;
  sessionToken?: string | null;
  subject?: string;
  sessionTtlMs?: number;
  audience?: string;
  capabilities?: UcanCapability[];
  expiresInMs?: number;
  ttlMs?: number;
};

const DEFAULT_BASE_URL = '/api/v1/public/auth/central';
const DEFAULT_ISSUER_PATH = 'issuer';
const DEFAULT_SESSION_PATH = 'session';
const DEFAULT_ISSUE_PATH = 'issue';
const DEFAULT_SESSION_TOKEN_KEY = 'centralUcanSessionToken';

let cachedCentralSessionToken: string | null = null;

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '');
}

function joinUrl(baseUrl: string, path: string): string {
  const trimmed = path.replace(/^\/+/, '');
  return `${normalizeBaseUrl(baseUrl)}/${trimmed}`;
}

function resolveBaseUrl(options?: CentralAuthBaseOptions): string {
  return options?.baseUrl || DEFAULT_BASE_URL;
}

function resolveFetcher(options?: CentralAuthBaseOptions): typeof fetch {
  return options?.fetcher || fetch;
}

function resolveCredentials(options?: CentralAuthBaseOptions): RequestCredentials {
  return options?.credentials ?? 'include';
}

function resolveSessionTokenKey(options?: CentralAuthBaseOptions): string {
  return options?.sessionTokenStorageKey || DEFAULT_SESSION_TOKEN_KEY;
}

function shouldStoreSessionToken(options?: CentralAuthBaseOptions): boolean {
  return options?.storeSessionToken !== false;
}

function parseObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

function parseEnvelopeData(payload: unknown): Record<string, unknown> {
  const root = parseObject(payload);
  if (Object.prototype.hasOwnProperty.call(root, 'data')) {
    return parseObject(root.data);
  }
  return root;
}

function parseStringField(obj: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === 'string') {
      return value;
    }
  }
  return undefined;
}

function parseNumberField(obj: Record<string, unknown>, keys: string[]): number | undefined {
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }
  }
  return undefined;
}

function parseCapabilitiesField(obj: Record<string, unknown>, keys: string[]): UcanCapability[] | undefined {
  for (const key of keys) {
    const value = obj[key];
    if (!Array.isArray(value)) continue;
    const caps = value
      .filter(item => item && typeof item === 'object')
      .map(item => normalizeUcanCapability(item as UcanCapability))
      .filter((cap): cap is UcanCapability => Boolean(cap));
    return caps;
  }
  return undefined;
}

function readStoredSessionToken(options?: CentralAuthBaseOptions): string | null {
  if (!shouldStoreSessionToken(options)) return null;
  if (typeof localStorage === 'undefined') return null;
  const key = resolveSessionTokenKey(options);
  return localStorage.getItem(key);
}

function persistSessionToken(token: string | null, options?: CentralAuthBaseOptions): void {
  cachedCentralSessionToken = token;
  if (!shouldStoreSessionToken(options)) return;
  if (typeof localStorage === 'undefined') return;
  const key = resolveSessionTokenKey(options);
  if (!token) {
    localStorage.removeItem(key);
  } else {
    localStorage.setItem(key, token);
  }
}

async function parseJsonBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

export function getCentralSessionToken(options?: CentralAuthBaseOptions): string | null {
  if (cachedCentralSessionToken) return cachedCentralSessionToken;
  const stored = readStoredSessionToken(options);
  if (stored) {
    cachedCentralSessionToken = stored;
  }
  return stored;
}

export function setCentralSessionToken(token: string | null, options?: CentralAuthBaseOptions): void {
  persistSessionToken(token, options);
}

export function clearCentralSessionToken(options?: CentralAuthBaseOptions): void {
  cachedCentralSessionToken = null;
  if (typeof localStorage === 'undefined') return;
  const key = resolveSessionTokenKey(options);
  localStorage.removeItem(key);
}

export async function getCentralIssuerInfo(
  options: CentralAuthBaseOptions = {}
): Promise<CentralIssuerInfo> {
  const fetcher = resolveFetcher(options);
  const credentials = resolveCredentials(options);
  const url = joinUrl(resolveBaseUrl(options), options.issuerPath || DEFAULT_ISSUER_PATH);
  const response = await fetcher(url, {
    method: 'GET',
    headers: {
      accept: 'application/json',
    },
    credentials,
  });
  const payload = await parseJsonBody(response);
  if (!response.ok) {
    throw new Error(`Central issuer request failed: ${response.status} ${JSON.stringify(payload)}`);
  }

  const data = parseEnvelopeData(payload);
  return {
    enabled: typeof data.enabled === 'boolean' ? data.enabled : undefined,
    issuerDid: parseStringField(data, ['issuerDid']),
    defaultAudience: parseStringField(data, ['defaultAudience']),
    defaultCapabilities: parseCapabilitiesField(data, ['defaultCapabilities']),
    response: payload,
  };
}

export async function createCentralSession(
  options: CreateCentralSessionOptions
): Promise<CentralSessionResult> {
  const subject = String(options?.subject || '').trim();
  if (!subject) {
    throw new Error('Missing subject');
  }
  const fetcher = resolveFetcher(options);
  const credentials = resolveCredentials(options);
  const url = joinUrl(resolveBaseUrl(options), options.sessionPath || DEFAULT_SESSION_PATH);
  const response = await fetcher(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      accept: 'application/json',
    },
    credentials,
    body: JSON.stringify({
      subject,
      sessionTtlMs: options.sessionTtlMs,
    }),
  });
  const payload = await parseJsonBody(response);
  if (!response.ok) {
    throw new Error(`Central session request failed: ${response.status} ${JSON.stringify(payload)}`);
  }

  const data = parseEnvelopeData(payload);
  const sessionToken = parseStringField(data, ['sessionToken']);
  if (!sessionToken) {
    throw new Error('Central session response missing sessionToken');
  }
  persistSessionToken(sessionToken, options);

  return {
    subject: parseStringField(data, ['subject']) || subject,
    sessionToken,
    expiresAt: parseNumberField(data, ['expiresAt']),
    issuerDid: parseStringField(data, ['issuerDid']),
    response: payload,
  };
}

export async function issueCentralUcan(
  options: IssueCentralUcanOptions = {}
): Promise<CentralUcanIssueResult> {
  const sessionToken = options.sessionToken || getCentralSessionToken(options);
  if (!sessionToken) {
    throw new Error('Missing central session token');
  }

  const normalizedCapabilities = options.capabilities
    ? normalizeUcanCapabilities(options.capabilities)
    : undefined;
  const fetcher = resolveFetcher(options);
  const credentials = resolveCredentials(options);
  const url = joinUrl(resolveBaseUrl(options), options.issuePath || DEFAULT_ISSUE_PATH);
  const response = await fetcher(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      accept: 'application/json',
      Authorization: `Bearer ${sessionToken}`,
    },
    credentials,
    body: JSON.stringify({
      audience: options.audience,
      capabilities: normalizedCapabilities,
      expiresInMs: options.expiresInMs,
      ttlMs: options.ttlMs,
    }),
  });
  const payload = await parseJsonBody(response);
  if (!response.ok) {
    throw new Error(`Central UCAN issue failed: ${response.status} ${JSON.stringify(payload)}`);
  }

  const data = parseEnvelopeData(payload);
  const ucan = parseStringField(data, ['ucan']);
  if (!ucan) {
    throw new Error('Central UCAN response missing ucan');
  }

  return {
    ucan,
    issuerDid: parseStringField(data, ['issuerDid']),
    subject: parseStringField(data, ['subject']),
    audience: parseStringField(data, ['audience']),
    capabilities: parseCapabilitiesField(data, ['capabilities']),
    exp: parseNumberField(data, ['exp']),
    nbf: parseNumberField(data, ['nbf']),
    iat: parseNumberField(data, ['iat']),
    response: payload,
  };
}

export async function createAndIssueCentralUcan(
  options: CreateAndIssueCentralUcanOptions
): Promise<CreateAndIssueCentralUcanResult> {
  const session = await createCentralSession({
    ...options,
    subject: options.subject,
    sessionTtlMs: options.sessionTtlMs,
  });
  const issue = await issueCentralUcan({
    ...options,
    sessionToken: session.sessionToken,
    audience: options.audience,
    capabilities: options.capabilities,
    expiresInMs: options.expiresInMs,
    ttlMs: options.ttlMs,
  });
  return { session, issue };
}

export async function authCentralUcanFetch(
  input: RequestInfo | URL,
  init: RequestInit = {},
  options: AuthCentralUcanFetchOptions = {}
): Promise<Response> {
  const fetcher = resolveFetcher(options);
  const credentials = resolveCredentials(options);
  let token = options.ucan || null;

  if (!token) {
    let sessionToken = options.sessionToken || getCentralSessionToken(options);
    if (!sessionToken) {
      if (!options.subject) {
        throw new Error('Missing central session token or subject');
      }
      const session = await createCentralSession({
        ...options,
        subject: options.subject,
        sessionTtlMs: options.sessionTtlMs,
      });
      sessionToken = session.sessionToken;
    }

    const issued = await issueCentralUcan({
      ...options,
      sessionToken,
      audience: options.audience,
      capabilities: options.capabilities,
      expiresInMs: options.expiresInMs,
      ttlMs: options.ttlMs,
    });
    token = issued.ucan;
  }

  const headers = new Headers(init.headers || {});
  headers.set('Authorization', `Bearer ${token}`);

  return fetcher(input, {
    ...init,
    headers,
    credentials,
  });
}
