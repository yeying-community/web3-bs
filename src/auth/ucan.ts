import { getAccounts, getChainId, getProvider, requireProvider } from './provider';
import { Eip1193Provider } from './types';

export type UcanCapability = {
  with?: string;
  can?: string;
  resource?: string;
  action?: string;
  nb?: unknown;
};

export type UcanRootProof = {
  type: 'siwe';
  iss: string;
  aud: string;
  cap: UcanCapability[];
  exp: number;
  nbf?: number;
  siwe: {
    message: string;
    signature: string;
  };
};

export type UcanProof = UcanRootProof | string;

export type UcanTokenPayload = {
  iss: string;
  aud: string;
  cap: UcanCapability[];
  exp: number;
  nbf?: number;
  prf: UcanProof[];
};

export type UcanSessionSource = 'wallet' | 'local';

export type UcanSessionRecord = {
  id: string;
  did: string;
  createdAt: number;
  expiresAt: number | null;
  source?: UcanSessionSource;
  privateKeyJwk?: JsonWebKey;
  publicKeyJwk?: JsonWebKey;
  root?: UcanRootProof;
};

export type UcanSessionKey = {
  id: string;
  did: string;
  createdAt: number;
  expiresAt: number | null;
  source?: UcanSessionSource;
  signer?: (signingInput: string, payload: UcanTokenPayload) => Promise<string>;
  privateKey?: CryptoKey;
};

export type CreateUcanSessionOptions = {
  id?: string;
  expiresInMs?: number;
  forceNew?: boolean;
  provider?: Eip1193Provider;
};

export type CreateRootUcanOptions = {
  provider?: Eip1193Provider;
  address?: string;
  session?: UcanSessionKey;
  sessionId?: string;
  capabilities: UcanCapability[];
  expiresInMs?: number;
  domain?: string;
  uri?: string;
  chainId?: string;
  statement?: string;
  nonce?: string;
  notBeforeMs?: number;
};

export type CreateUcanTokenOptions = {
  issuer?: UcanSessionKey;
  sessionId?: string;
  provider?: Eip1193Provider;
  audience: string;
  capabilities: UcanCapability[];
  expiresInMs?: number;
  notBeforeMs?: number;
  proofs?: UcanProof[];
};

export type UcanFetchOptions = {
  ucan?: string;
  audience?: string;
  capabilities?: UcanCapability[];
  issuer?: UcanSessionKey;
  sessionId?: string;
  provider?: Eip1193Provider;
  proofs?: UcanProof[];
  expiresInMs?: number;
  notBeforeMs?: number;
  fetcher?: typeof fetch;
};

const DEFAULT_SESSION_ID = 'default';
const DEFAULT_SESSION_TTL = 24 * 60 * 60 * 1000;
const DEFAULT_UCAN_TTL = 5 * 60 * 1000;
const DB_NAME = 'yeying-web3';
const DB_STORE = 'ucan-sessions';
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const DID_KEY_ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

const textEncoder = new TextEncoder();

function toBase64Url(data: Uint8Array | ArrayBuffer): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function normalizeActionExpression(raw: string): string {
  const normalized = String(raw || '').trim().toLowerCase().replace(/\|/g, ',');
  if (!normalized) return '';
  const parts = normalized
    .split(',')
    .map(part => part.trim())
    .filter(Boolean);
  if (!parts.length) return '';
  return Array.from(new Set(parts)).join(',');
}

export function getCapabilityResource(cap: UcanCapability | null | undefined): string {
  if (!cap || typeof cap !== 'object') return '';
  const withValue = typeof cap.with === 'string' ? cap.with.trim() : '';
  if (withValue) return withValue;
  return typeof cap.resource === 'string' ? cap.resource.trim() : '';
}

export function getCapabilityAction(cap: UcanCapability | null | undefined): string {
  if (!cap || typeof cap !== 'object') return '';
  const canValue = typeof cap.can === 'string' ? cap.can.trim() : '';
  if (canValue) return normalizeActionExpression(canValue);
  const actionValue = typeof cap.action === 'string' ? cap.action.trim() : '';
  return normalizeActionExpression(actionValue);
}

export function normalizeUcanCapability(
  cap: UcanCapability | null | undefined,
  options: { includeLegacyAliases?: boolean } = {}
): UcanCapability | null {
  const includeLegacyAliases = options.includeLegacyAliases !== false;
  const resource = getCapabilityResource(cap);
  const action = getCapabilityAction(cap);
  if (!resource || !action) return null;
  const normalized: UcanCapability = {
    with: resource,
    can: action,
  };
  if (includeLegacyAliases) {
    normalized.resource = resource;
    normalized.action = action;
  }
  if (cap && Object.prototype.hasOwnProperty.call(cap, 'nb')) {
    normalized.nb = cap.nb;
  }
  return normalized;
}

export function normalizeUcanCapabilities(
  caps: UcanCapability[] | undefined,
  options: { includeLegacyAliases?: boolean } = {}
): UcanCapability[] {
  const includeLegacyAliases = options.includeLegacyAliases !== false;
  const seen = new Set<string>();
  const result: UcanCapability[] = [];
  for (const cap of caps || []) {
    const normalized = normalizeUcanCapability(cap, { includeLegacyAliases });
    if (!normalized) continue;
    const key = `${normalized.with}|${normalized.can}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(normalized);
  }
  return result;
}

function encodeJson(value: unknown): string {
  return toBase64Url(textEncoder.encode(JSON.stringify(value)));
}

function randomNonce(bytes = 16): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return Array.from(buffer)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function normalizeExpiry(exp: number | undefined, fallbackMs: number): number {
  if (typeof exp === 'number' && !Number.isNaN(exp)) return exp;
  return Date.now() + fallbackMs;
}

function isSessionExpired(expiresAt: number | null | undefined, nowMs: number = Date.now()): boolean {
  return typeof expiresAt === 'number' && nowMs >= expiresAt;
}

function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) + BigInt(byte);
  }
  let encoded = '';
  while (value > 0n) {
    const mod = Number(value % 58n);
    encoded = `${BASE58_ALPHABET[mod]}${encoded}`;
    value /= 58n;
  }
  let leadingZeroCount = 0;
  while (leadingZeroCount < bytes.length && bytes[leadingZeroCount] === 0) {
    leadingZeroCount += 1;
  }
  if (leadingZeroCount > 0) {
    encoded = `${'1'.repeat(leadingZeroCount)}${encoded}`;
  }
  return encoded || '1';
}

function ensureWebCrypto(): Crypto {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto not available for UCAN session');
  }
  return crypto;
}

function parseSessionId(options: CreateUcanSessionOptions): string {
  return options.id || DEFAULT_SESSION_ID;
}

function isLocalSessionRecord(record: UcanSessionRecord | null): boolean {
  return Boolean(record?.source === 'local' || record?.privateKeyJwk);
}

async function buildDidKey(publicKey: CryptoKey): Promise<string> {
  const webCrypto = ensureWebCrypto();
  const raw = new Uint8Array(await webCrypto.subtle.exportKey('raw', publicKey));
  const prefixed = new Uint8Array(DID_KEY_ED25519_MULTICODEC.length + raw.length);
  prefixed.set(DID_KEY_ED25519_MULTICODEC, 0);
  prefixed.set(raw, DID_KEY_ED25519_MULTICODEC.length);
  return `did:key:z${encodeBase58(prefixed)}`;
}

async function importLocalPrivateKey(privateKeyJwk: JsonWebKey): Promise<CryptoKey> {
  const webCrypto = ensureWebCrypto();
  return await webCrypto.subtle.importKey('jwk', privateKeyJwk, 'Ed25519', true, ['sign']);
}

async function loadLocalSessionFromRecord(
  id: string,
  record: UcanSessionRecord | null
): Promise<UcanSessionKey | null> {
  if (!record || !isLocalSessionRecord(record) || !record.privateKeyJwk) {
    return null;
  }
  if (isSessionExpired(record.expiresAt)) {
    await deleteSessionRecord(id);
    return null;
  }
  try {
    const privateKey = await importLocalPrivateKey(record.privateKeyJwk);
    return {
      id: record.id || id,
      did: record.did,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      source: 'local',
      privateKey,
    };
  } catch {
    return null;
  }
}

function shouldKeepRootForSession(root: UcanRootProof | undefined, did: string, nowMs: number): boolean {
  if (!root) return false;
  if (root.aud && root.aud !== did) return false;
  if (isRootExpired(root, nowMs)) return false;
  return true;
}

async function createLocalSession(
  options: CreateUcanSessionOptions,
  record: UcanSessionRecord | null
): Promise<UcanSessionKey> {
  const webCrypto = ensureWebCrypto();
  const sessionId = parseSessionId(options);
  if (!options.forceNew) {
    const existing = await loadLocalSessionFromRecord(sessionId, record);
    if (existing) return existing;
  }

  const pair = (await webCrypto.subtle.generateKey(
    'Ed25519',
    true,
    ['sign', 'verify']
  )) as CryptoKeyPair;
  const [privateKeyJwk, publicKeyJwk, did] = await Promise.all([
    webCrypto.subtle.exportKey('jwk', pair.privateKey),
    webCrypto.subtle.exportKey('jwk', pair.publicKey),
    buildDidKey(pair.publicKey),
  ]);

  const createdAt = Date.now();
  const expiresAt = normalizeExpiry(undefined, options.expiresInMs ?? DEFAULT_SESSION_TTL);
  const root = shouldKeepRootForSession(record?.root, did, createdAt) ? record?.root : undefined;

  await writeSessionRecord({
    id: sessionId,
    did,
    createdAt,
    expiresAt,
    source: 'local',
    privateKeyJwk,
    publicKeyJwk,
    root,
  });

  return {
    id: sessionId,
    did,
    createdAt,
    expiresAt,
    source: 'local',
    privateKey: pair.privateKey,
  };
}


function openDb(): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') {
    return Promise.reject(new Error('IndexedDB not available'));
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(DB_STORE)) {
        db.createObjectStore(DB_STORE, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function readSessionRecord(id: string): Promise<UcanSessionRecord | null> {
  try {
    const db = await openDb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(DB_STORE, 'readonly');
      const store = tx.objectStore(DB_STORE);
      const request = store.get(id);
      request.onsuccess = () => resolve((request.result as UcanSessionRecord) || null);
      request.onerror = () => reject(request.error);
    });
  } catch {
    return null;
  }
}

async function writeSessionRecord(record: UcanSessionRecord): Promise<void> {
  try {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(DB_STORE, 'readwrite');
      const store = tx.objectStore(DB_STORE);
      const request = store.put(record);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch {
    // ignore storage failures
  }
}

async function deleteSessionRecord(id: string): Promise<void> {
  try {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(DB_STORE, 'readwrite');
      const store = tx.objectStore(DB_STORE);
      const request = store.delete(id);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch {
    // ignore storage failures
  }
}

export async function getUcanSession(
  id: string = DEFAULT_SESSION_ID,
  provider?: Eip1193Provider
): Promise<UcanSessionKey | null> {
  const record = await readSessionRecord(id);
  const walletProvider = provider || (typeof window !== 'undefined'
    ? await getProvider({ preferYeYing: true })
    : null);
  if (walletProvider) {
    try {
      return await requestWalletUcanSession(walletProvider, { id });
    } catch {
      return await loadLocalSessionFromRecord(id, record);
    }
  }
  return await loadLocalSessionFromRecord(id, record);
}

async function requestWalletUcanSession(
  provider: Eip1193Provider,
  options: CreateUcanSessionOptions
): Promise<UcanSessionKey> {
  const sessionId = options.id || DEFAULT_SESSION_ID;
  const result = (await provider.request({
    method: 'yeying_ucan_session',
    params: [
      {
        sessionId,
        expiresInMs: options.expiresInMs,
        forceNew: options.forceNew,
      },
    ],
  })) as {
    id?: string;
    did?: string;
    createdAt?: number;
    expiresAt?: number | null;
  };

  if (!result || typeof result.did !== 'string') {
    throw new Error('Invalid wallet UCAN session response');
  }

  const createdAt = typeof result.createdAt === 'number' ? result.createdAt : Date.now();
  const expiresAt = typeof result.expiresAt === 'number' ? result.expiresAt : null;
  const existing = await readSessionRecord(sessionId);
  const nextRecord: UcanSessionRecord = {
    id: result.id || sessionId,
    did: result.did,
    createdAt,
    expiresAt,
    source: 'wallet',
    root: existing?.root,
  };
  if (nextRecord.root && nextRecord.root.aud && nextRecord.root.aud !== nextRecord.did) {
    nextRecord.root = undefined;
  }
  await writeSessionRecord(nextRecord);

  return {
    id: result.id || sessionId,
    did: result.did,
    createdAt,
    expiresAt,
    source: 'wallet',
    signer: async (signingInput: string, payload: UcanTokenPayload) => {
      const signatureResult = (await provider.request({
        method: 'yeying_ucan_sign',
        params: [
          {
            sessionId,
            signingInput,
            payload,
          },
        ],
      })) as { signature?: string } | string;

      if (typeof signatureResult === 'string') {
        return signatureResult;
      }
      if (signatureResult && typeof signatureResult.signature === 'string') {
        return signatureResult.signature;
      }
      throw new Error('Invalid wallet UCAN signature response');
    },
  };
}

export async function createUcanSession(
  options: CreateUcanSessionOptions = {}
): Promise<UcanSessionKey> {
  const sessionId = parseSessionId(options);
  const record = await readSessionRecord(sessionId);
  const provider = options.provider || (typeof window !== 'undefined'
    ? await getProvider({ preferYeYing: true })
    : null);
  if (provider) {
    try {
      return await requestWalletUcanSession(provider, { ...options, id: sessionId });
    } catch {
      // fallback to local ed25519 session
    }
  }
  return await createLocalSession({ ...options, id: sessionId }, record);
}

export async function clearUcanSession(id: string = DEFAULT_SESSION_ID): Promise<void> {
  await deleteSessionRecord(id);
}

export async function storeUcanRoot(
  root: UcanRootProof,
  id: string = DEFAULT_SESSION_ID
): Promise<void> {
  const record = await readSessionRecord(id);
  const createdAt = record?.createdAt ?? Date.now();
  const expiresAt = record?.expiresAt ?? null;
  const did = record?.did || root.aud;
  const nextRecord: UcanSessionRecord = {
    ...(record || {}),
    id,
    did,
    createdAt,
    expiresAt,
    root,
  };
  await writeSessionRecord(nextRecord);
}

export async function getStoredUcanRoot(id: string = DEFAULT_SESSION_ID): Promise<UcanRootProof | null> {
  const record = await readSessionRecord(id);
  return record?.root || null;
}

function capsEqual(a: UcanCapability[] | undefined, b: UcanCapability[] | undefined): boolean {
  const left = normalizeUcanCapabilities(a, { includeLegacyAliases: false });
  const right = normalizeUcanCapabilities(b, { includeLegacyAliases: false });
  return JSON.stringify(left) === JSON.stringify(right);
}

function isRootExpired(root: UcanRootProof, nowMs: number): boolean {
  return Boolean(root.exp && nowMs > root.exp);
}

export async function getOrCreateUcanRoot(options: CreateRootUcanOptions): Promise<UcanRootProof> {
  const provider = options.provider || (await requireProvider());
  const session = options.session || (await createUcanSession({ id: options.sessionId, provider }));
  const nowMs = Date.now();
  const stored = await getStoredUcanRoot(session.id);
  if (
    stored &&
    (!stored.aud || stored.aud === session.did) &&
    capsEqual(stored.cap, options.capabilities) &&
    !isRootExpired(stored, nowMs)
  ) {
    return stored;
  }

  return await createRootUcan({ ...options, provider, session });
}

function buildUcanStatement(payload: Record<string, unknown>): string {
  return `UCAN-AUTH ${JSON.stringify(payload)}`;
}

function buildSiweMessage(params: {
  domain: string;
  address: string;
  statement: string;
  uri: string;
  chainId: string;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
}): string {
  const lines = [
    `${params.domain} wants you to sign in with your Ethereum account:`,
    params.address,
    '',
    params.statement,
    '',
    `URI: ${params.uri}`,
    'Version: 1',
    `Chain ID: ${params.chainId}`,
    `Nonce: ${params.nonce}`,
    `Issued At: ${params.issuedAt}`,
  ];
  if (params.expirationTime) {
    lines.push(`Expiration Time: ${params.expirationTime}`);
  }
  return lines.join('\n');
}

async function resolveAddress(provider: Eip1193Provider, address?: string): Promise<string> {
  if (address) return address;
  let accounts = await getAccounts(provider);
  if (!accounts[0]) {
    const requested = (await provider.request({
      method: 'eth_requestAccounts',
    })) as string[];
    if (Array.isArray(requested)) {
      accounts = requested;
    }
  }
  if (!accounts[0]) throw new Error('No account available');
  return accounts[0];
}

async function signWithProvider(
  provider: Eip1193Provider,
  address: string,
  message: string
): Promise<string> {
  const signature = await provider.request({
    method: 'personal_sign',
    params: [message, address],
  });
  if (typeof signature !== 'string') {
    throw new Error('Invalid signature response');
  }
  return signature;
}

export async function createRootUcan(options: CreateRootUcanOptions): Promise<UcanRootProof> {
  const provider = options.provider || (await requireProvider());
  const session = options.session || (await createUcanSession({ id: options.sessionId, provider }));
  const address = await resolveAddress(provider, options.address);
  const chainId = options.chainId || (await getChainId(provider)) || '1';
  const domain = options.domain || (typeof window !== 'undefined' ? window.location.host : '127.0.0.1');
  const uri = options.uri || (typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1');
  const nonce = options.nonce || randomNonce(8);
  const exp = normalizeExpiry(undefined, options.expiresInMs ?? DEFAULT_SESSION_TTL);
  const nbf = options.notBeforeMs;

  const normalizedCapabilities = normalizeUcanCapabilities(options.capabilities);
  if (!normalizedCapabilities.length) {
    throw new Error('Missing UCAN capabilities');
  }

  const statementPayload: Record<string, unknown> = {
    aud: session.did,
    cap: normalizedCapabilities,
    exp,
  };
  if (nbf) statementPayload.nbf = nbf;

  const statement = options.statement || buildUcanStatement(statementPayload);
  const issuedAt = new Date().toISOString();
  const expirationTime = new Date(exp).toISOString();
  const message = buildSiweMessage({
    domain,
    address,
    statement,
    uri,
    chainId,
    nonce,
    issuedAt,
    expirationTime,
  });

  const signature = await signWithProvider(provider, address, message);

  const root: UcanRootProof = {
    type: 'siwe',
    iss: `did:pkh:eth:${address.toLowerCase()}`,
    aud: session.did,
    cap: normalizedCapabilities,
    exp,
    nbf,
    siwe: {
      message,
      signature,
    },
  };

  await storeUcanRoot(root, session.id);

  return root;
}

async function signUcanPayload(payload: UcanTokenPayload, session: UcanSessionKey): Promise<string> {
  const header = { alg: 'EdDSA', typ: 'UCAN' };
  const headerB64 = encodeJson(header);
  const payloadB64 = encodeJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  let signatureB64: string;

  if (session.signer) {
    signatureB64 = await session.signer(signingInput, payload);
  } else {
    if (!session.privateKey) {
      throw new Error('Missing UCAN session key');
    }
    const data = textEncoder.encode(signingInput);
    const signature = await crypto.subtle.sign('Ed25519', session.privateKey, data);
    signatureB64 = toBase64Url(signature);
  }
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

async function resolveProofs(
  options: CreateUcanTokenOptions,
  issuer?: UcanSessionKey
): Promise<UcanProof[]> {
  if (options.proofs && options.proofs.length > 0) return options.proofs;
  const stored = await getStoredUcanRoot(options.sessionId || DEFAULT_SESSION_ID);
  if (!stored) {
    throw new Error('Missing UCAN proof chain');
  }
  if (issuer?.did && stored.aud && stored.aud !== issuer.did) {
    throw new Error('UCAN root audience mismatch');
  }
  return [stored];
}

export async function createDelegationUcan(options: CreateUcanTokenOptions): Promise<string> {
  const issuer = options.issuer || (await createUcanSession({
    id: options.sessionId,
    provider: options.provider,
  }));
  if (!issuer) throw new Error('Missing UCAN session key');
  const normalizedCapabilities = normalizeUcanCapabilities(options.capabilities);
  if (!normalizedCapabilities.length) {
    throw new Error('Missing UCAN capabilities');
  }
  const exp = normalizeExpiry(undefined, options.expiresInMs ?? DEFAULT_UCAN_TTL);
  const payload: UcanTokenPayload = {
    iss: issuer.did,
    aud: options.audience,
    cap: normalizedCapabilities,
    exp,
    nbf: options.notBeforeMs,
    prf: await resolveProofs(options, issuer),
  };
  return await signUcanPayload(payload, issuer);
}

export async function createInvocationUcan(options: CreateUcanTokenOptions): Promise<string> {
  const issuer = options.issuer || (await createUcanSession({
    id: options.sessionId,
    provider: options.provider,
  }));
  if (!issuer) throw new Error('Missing UCAN session key');
  const normalizedCapabilities = normalizeUcanCapabilities(options.capabilities);
  if (!normalizedCapabilities.length) {
    throw new Error('Missing UCAN capabilities');
  }
  const exp = normalizeExpiry(undefined, options.expiresInMs ?? DEFAULT_UCAN_TTL);
  const payload: UcanTokenPayload = {
    iss: issuer.did,
    aud: options.audience,
    cap: normalizedCapabilities,
    exp,
    nbf: options.notBeforeMs,
    prf: await resolveProofs(options, issuer),
  };
  return await signUcanPayload(payload, issuer);
}

export async function authUcanFetch(
  input: RequestInfo | URL,
  init: RequestInit = {},
  options: UcanFetchOptions = {}
): Promise<Response> {
  const fetcher = options.fetcher || fetch;
  let token = options.ucan;
  if (!token) {
    if (!options.audience || !options.capabilities) {
      throw new Error('Missing UCAN audience or capabilities');
    }
    token = await createInvocationUcan({
      issuer: options.issuer,
      sessionId: options.sessionId,
      provider: options.provider,
      audience: options.audience,
      capabilities: options.capabilities,
      expiresInMs: options.expiresInMs,
      notBeforeMs: options.notBeforeMs,
      proofs: options.proofs,
    });
  }

  const headers = new Headers(init.headers || {});
  headers.set('Authorization', `Bearer ${token}`);

  return fetcher(input, {
    ...init,
    headers,
  });
}
