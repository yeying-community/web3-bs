import { requireProvider } from './auth/provider';
import { loginWithChallenge } from './auth/siwe';
import {
  createInvocationUcan,
  createUcanSession,
  getCapabilityAction,
  getCapabilityResource,
  getOrCreateUcanRoot,
  normalizeUcanCapabilities,
  UcanCapability,
  UcanRootProof,
  UcanSessionKey,
  UcanTokenPayload,
} from './auth/ucan';
import { Eip1193Provider, LoginWithChallengeOptions } from './auth/types';
import { createWebDavClient, WebDavClient } from './storage/webdav';

type CachedUcanToken = {
  token: string;
  exp: number;
  nbf?: number;
};

const tokenCache = new Map<string, CachedUcanToken>();
const TOKEN_SKEW_MS = 5000;
const DEFAULT_APP_ACTION = 'write';
const LOOPBACK_HOST_ALIASES = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '0:0:0:0:0:0:0:1',
  '0.0.0.0',
]);

export type InitWebDavStorageOptions = {
  baseUrl: string;
  audience: string;
  prefix?: string;
  appDir?: string;
  appId?: string;
  appAction?: string;
  ensureAppDir?: boolean;
  capabilities?: UcanCapability[];
  invocationCapabilities?: UcanCapability[];
  provider?: Eip1193Provider;
  sessionId?: string;
  session?: UcanSessionKey;
  root?: UcanRootProof;
  rootExpiresInMs?: number;
  invocationExpiresInMs?: number;
  notBeforeMs?: number;
  fetcher?: typeof fetch;
  credentials?: RequestCredentials;
};

export type InitWebDavStorageResult = {
  client: WebDavClient;
  token: string;
  appDir?: string;
  session: UcanSessionKey;
  root: UcanRootProof;
};

export type InitDappSessionOptions = {
  provider?: Eip1193Provider;
  address?: string;
  appAuth?: LoginWithChallengeOptions;
  webdav?: InitWebDavStorageOptions;
};

export type InitDappSessionResult = {
  provider: Eip1193Provider;
  address?: string;
  appLogin?: Awaited<ReturnType<typeof loginWithChallenge>>;
  ucanSession?: UcanSessionKey;
  ucanRoot?: UcanRootProof;
  webdavClient?: WebDavClient;
  webdavToken?: string;
  webdavAppDir?: string;
};

export type AppIdLocationLike = {
  host?: string | null;
  hostname?: string | null;
  port?: string | number | null;
};

function normalizeAppDir(path: string): string {
  const trimmed = path.trim();
  if (!trimmed) return '/';
  let next = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  next = next.replace(/\/+$/, '');
  return next || '/';
}

function sanitizeAppId(appId: string): string {
  return appId.trim().replace(/[^a-zA-Z0-9._-]/g, '-');
}

function parseHostPort(rawHost: string): { hostname: string; port: string } {
  const host = rawHost.trim();
  if (!host) return { hostname: '', port: '' };

  const bracketMatch = host.match(/^\[([^\]]+)\](?::([0-9]+))?$/);
  if (bracketMatch) {
    return {
      hostname: bracketMatch[1] || '',
      port: bracketMatch[2] || '',
    };
  }

  const firstColon = host.indexOf(':');
  const lastColon = host.lastIndexOf(':');
  if (firstColon > -1 && firstColon === lastColon) {
    const hostname = host.slice(0, firstColon).trim();
    const port = host.slice(firstColon + 1).trim();
    if (/^[0-9]+$/.test(port)) {
      return { hostname, port };
    }
  }

  return { hostname: host, port: '' };
}

export function normalizeAppHostnameForAppId(hostname: string): string {
  const normalized = (hostname || '').trim().toLowerCase();
  if (!normalized) return '';
  const bare = normalized.replace(/^\[(.*)\]$/, '$1');
  if (LOOPBACK_HOST_ALIASES.has(normalized) || LOOPBACK_HOST_ALIASES.has(bare)) {
    return 'localhost';
  }
  return bare;
}

function buildSanitizedAppId(hostname: string, port?: string | number | null): string {
  const normalizedHostname = normalizeAppHostnameForAppId(hostname);
  if (!normalizedHostname) return '';
  const normalizedPort =
    port === undefined || port === null ? '' : String(port).trim();
  const host = normalizedPort
    ? `${normalizedHostname}:${normalizedPort}`
    : normalizedHostname;
  return sanitizeAppId(host);
}

export function deriveAppIdFromHost(host: string): string {
  const parsed = parseHostPort(host || '');
  return buildSanitizedAppId(parsed.hostname, parsed.port);
}

export function deriveAppIdFromLocation(
  locationLike?: AppIdLocationLike
): string {
  const source =
    locationLike ||
    (typeof window !== 'undefined' ? (window.location as AppIdLocationLike) : undefined);
  if (!source) return '';

  const hostname = typeof source.hostname === 'string' ? source.hostname : '';
  const port = source.port;
  if (hostname) {
    const appId = buildSanitizedAppId(hostname, port);
    if (appId) return appId;
  }

  if (typeof source.host === 'string') {
    return deriveAppIdFromHost(source.host);
  }

  return '';
}

function normalizeAction(action?: string): string | null {
  const trimmed = (action || '').trim();
  return trimmed ? trimmed : null;
}

function buildAppCapability(options: InitWebDavStorageOptions): UcanCapability | null {
  if (!options.appId) return null;
  const action = normalizeAction(options.appAction) || DEFAULT_APP_ACTION;
  const resource = `app:all:${sanitizeAppId(options.appId)}`;
  return {
    with: resource,
    can: action,
    resource,
    action,
  };
}

function hasAppCapability(caps: UcanCapability[]): boolean {
  return (caps || []).some(cap => getCapabilityResource(cap).startsWith('app:'));
}

function dedupeCapabilities(caps: UcanCapability[]): UcanCapability[] {
  return normalizeUcanCapabilities(caps);
}

function ensureAppCapability(caps: UcanCapability[], options: InitWebDavStorageOptions): UcanCapability[] {
  const appCap = buildAppCapability(options);
  if (!appCap) return caps || [];
  if (hasAppCapability(caps || [])) return caps || [];
  return dedupeCapabilities([...(caps || []), appCap]);
}

function resolveAppDir(options: InitWebDavStorageOptions): string | undefined {
  if (options.appDir) {
    return normalizeAppDir(options.appDir);
  }
  if (options.appId) {
    return normalizeAppDir(`/apps/${sanitizeAppId(options.appId)}`);
  }
  return undefined;
}

function buildCapsKey(caps: UcanCapability[]): string {
  const canonical = (caps || [])
    .map(cap => ({
      with: getCapabilityResource(cap),
      can: getCapabilityAction(cap),
    }))
    .filter(cap => Boolean(cap.with && cap.can));
  return JSON.stringify(canonical);
}

function buildTokenCacheKey(issuer: UcanSessionKey, audience: string, caps: UcanCapability[]): string {
  return `${issuer.did}|${audience}|${buildCapsKey(caps)}`;
}

function resolveWebdavCaps(options: InitWebDavStorageOptions): UcanCapability[] {
  const baseCaps = options.capabilities || options.root?.cap || [];
  return ensureAppCapability(baseCaps, options);
}

function resolveInvocationCaps(
  options: InitWebDavStorageOptions,
  fallbackCaps: UcanCapability[]
): UcanCapability[] {
  const caps = options.invocationCapabilities || fallbackCaps;
  return ensureAppCapability(caps, options);
}

function isTokenValid(entry: CachedUcanToken, nowMs: number): boolean {
  if (!entry.exp) return false;
  if (entry.nbf && nowMs < entry.nbf) return false;
  return entry.exp - TOKEN_SKEW_MS > nowMs;
}

function decodeBase64Url(input: string): string | null {
  if (!input) return null;
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  try {
    if (typeof atob === 'function') {
      return atob(padded);
    }
  } catch {
    // ignore
  }
  try {
    const nodeBuffer = (globalThis as {
      Buffer?: { from: (input: string, encoding: string) => { toString: (encoding: string) => string } };
    }).Buffer;
    if (nodeBuffer) {
      return nodeBuffer.from(padded, 'base64').toString('utf8');
    }
  } catch {
    return null;
  }
  return null;
}

function decodeUcanPayload(token: string): UcanTokenPayload | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  const decoded = decodeBase64Url(parts[1]);
  if (!decoded) return null;
  try {
    return JSON.parse(decoded) as UcanTokenPayload;
  } catch {
    return null;
  }
}

async function getCachedInvocationToken(options: {
  issuer: UcanSessionKey;
  audience: string;
  capabilities: UcanCapability[];
  proofs: UcanRootProof[];
  expiresInMs?: number;
  notBeforeMs?: number;
}): Promise<string> {
  const cacheKey = buildTokenCacheKey(options.issuer, options.audience, options.capabilities);
  const cached = tokenCache.get(cacheKey);
  const nowMs = Date.now();
  if (cached && isTokenValid(cached, nowMs)) {
    return cached.token;
  }

  const token = await createInvocationUcan({
    issuer: options.issuer,
    audience: options.audience,
    capabilities: options.capabilities,
    proofs: options.proofs,
    expiresInMs: options.expiresInMs,
    notBeforeMs: options.notBeforeMs,
  });

  const payload = decodeUcanPayload(token);
  if (payload && typeof payload.exp === 'number') {
    tokenCache.set(cacheKey, {
      token,
      exp: payload.exp,
      nbf: payload.nbf,
    });
  }

  return token;
}

export async function initWebDavStorage(
  options: InitWebDavStorageOptions
): Promise<InitWebDavStorageResult> {
  const caps = resolveWebdavCaps(options);
  if (!caps || caps.length === 0) {
    throw new Error('Missing UCAN capabilities for WebDAV');
  }

  const needsProvider = !options.session || !options.root;
  const provider =
    options.provider || (needsProvider ? await requireProvider() : undefined);

  const session =
    options.session ||
    (await createUcanSession({
      id: options.sessionId,
      provider,
    }));

  const nowMs = Date.now();
  let root = options.root;
  if (root && root.aud && root.aud !== session.did) {
    root = undefined;
  }
  if (root && buildCapsKey(root.cap) !== buildCapsKey(caps)) {
    root = undefined;
  }
  if (root && root.exp && nowMs > root.exp) {
    root = undefined;
  }

  if (!root) {
    root = await getOrCreateUcanRoot({
      provider: provider || (await requireProvider()),
      session,
      capabilities: caps,
      expiresInMs: options.rootExpiresInMs,
    });
  }

  const invocationCaps = resolveInvocationCaps(options, caps);

  const token = await getCachedInvocationToken({
    issuer: session,
    audience: options.audience,
    capabilities: invocationCaps,
    proofs: [root],
    expiresInMs: options.invocationExpiresInMs,
    notBeforeMs: options.notBeforeMs,
  });

  const client = createWebDavClient({
    baseUrl: options.baseUrl,
    prefix: options.prefix,
    token,
    fetcher: options.fetcher,
    credentials: options.credentials,
  });

  const appDir = resolveAppDir(options);
  if (appDir && options.ensureAppDir !== false) {
    await client.ensureDirectory(appDir);
  }

  return {
    client,
    token,
    appDir,
    session,
    root,
  };
}

export async function initDappSession(
  options: InitDappSessionOptions
): Promise<InitDappSessionResult> {
  if (!options.appAuth && !options.webdav) {
    throw new Error('No init options provided');
  }

  const provider =
    options.provider ||
    options.appAuth?.provider ||
    options.webdav?.provider ||
    (await requireProvider());

  const result: InitDappSessionResult = {
    provider,
    address: options.address,
  };

  if (options.appAuth) {
    const appLogin = await loginWithChallenge({
      ...options.appAuth,
      provider: options.appAuth.provider || provider,
      address: options.appAuth.address || options.address,
    });
    result.appLogin = appLogin;
    result.address = appLogin.address;
  }

  if (options.webdav) {
    const webdav = await initWebDavStorage({
      ...options.webdav,
      provider: options.webdav.provider || provider,
    });
    result.ucanSession = webdav.session;
    result.ucanRoot = webdav.root;
    result.webdavClient = webdav.client;
    result.webdavToken = webdav.token;
    result.webdavAppDir = webdav.appDir;
  }

  return result;
}
