const express = require('express');
const cors = require('cors');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

const PORT = Number(process.env.PORT || 3203);
const JWT_SECRET = process.env.JWT_SECRET || 'replace-this-in-production';
const ACCESS_TTL_MS = Number(process.env.ACCESS_TTL_MS || 15 * 60 * 1000);
const REFRESH_TTL_MS = Number(process.env.REFRESH_TTL_MS || 7 * 24 * 60 * 60 * 1000);
const COOKIE_SAMESITE = (process.env.COOKIE_SAMESITE || 'lax').toLowerCase();
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || '').toLowerCase() === 'true';
const UCAN_AUD = process.env.UCAN_AUD || `did:web:127.0.0.1:${PORT}`;
// Recommended: UCAN_RESOURCE=app:<appId> and UCAN_ACTION=read,write; appId = frontend domain or IP:port.
const UCAN_RESOURCE = process.env.UCAN_RESOURCE || 'profile';
const UCAN_ACTION = process.env.UCAN_ACTION || 'read';

const multiPorts = [3201, 3202, 3203, 3204];
const defaultOrigins = [
  `http://127.0.0.1:${PORT}`,
  `http://127.0.0.1:${PORT}`,
  `http://[::]:${PORT}`,
  'http://127.0.0.1:8000',
  'http://127.0.0.1:8000',
  'http://[::]:8000',
  'http://127.0.0.1:8001',
  'http://127.0.0.1:8001',
  'http://[::]:8001',
];
multiPorts.forEach(port => {
  defaultOrigins.push(
    `http://127.0.0.1:${port}`,
    `http://127.0.0.1:${port}`,
    `http://[::]:${port}`
  );
});

const allowedOrigins = new Set(
  (process.env.CORS_ORIGINS || defaultOrigins.join(','))
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean)
);

const corsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    logInfo('HTTP', {
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - start,
      origin: req.headers.origin || '',
    });
  });
  next();
});

const challenges = new Map();
const refreshStore = new Map();
const REQUIRED_UCAN_CAP = { resource: UCAN_RESOURCE, action: UCAN_ACTION };

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function logInfo(message, meta) {
  const prefix = `[${new Date().toISOString()}]`;
  if (meta !== undefined) {
    console.log(prefix, message, meta);
    return;
  }
  console.log(prefix, message);
}

function logWarn(message, meta) {
  const prefix = `[${new Date().toISOString()}]`;
  if (meta !== undefined) {
    console.warn(prefix, message, meta);
    return;
  }
  console.warn(prefix, message);
}

function logError(message, meta) {
  const prefix = `[${new Date().toISOString()}]`;
  if (meta !== undefined) {
    console.error(prefix, message, meta);
    return;
  }
  console.error(prefix, message);
}

function preview(value, keep = 8) {
  if (!value || typeof value !== 'string') return '';
  if (value.length <= keep * 2 + 3) return value;
  return `${value.slice(0, keep)}...${value.slice(-keep)}`;
}

function summarizeCaps(caps) {
  if (!Array.isArray(caps)) return [];
  return caps
    .filter(cap => cap && typeof cap.resource === 'string' && typeof cap.action === 'string')
    .map(cap => `${cap.resource}:${cap.action}`);
}

function now() {
  return Date.now();
}

function ok(data) {
  return { code: 0, message: 'ok', data, timestamp: now() };
}

function fail(code, message) {
  return { code, message, data: null, timestamp: now() };
}

function base64UrlDecode(input) {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + pad, 'base64');
}

function decodeJsonSegment(segment) {
  const decoded = base64UrlDecode(segment).toString('utf8');
  return JSON.parse(decoded);
}

function base58Decode(value) {
  let bytes = [0];
  for (const char of value) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index < 0) {
      throw new Error('Invalid base58 character');
    }
    let carry = index;
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let zeros = 0;
  while (zeros < value.length && value[zeros] === '1') zeros += 1;
  const output = Buffer.alloc(zeros + bytes.length);
  for (let i = 0; i < zeros; i += 1) output[i] = 0;
  for (let i = 0; i < bytes.length; i += 1) {
    output[output.length - 1 - i] = bytes[i];
  }
  return output;
}

function didKeyToPublicKey(did) {
  if (!did || typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new Error('Invalid did:key format');
  }
  const decoded = base58Decode(did.slice('did:key:z'.length));
  if (decoded.length < 3 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('Unsupported did:key type');
  }
  return decoded.slice(2);
}

function createEd25519PublicKey(raw) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  const der = Buffer.concat([prefix, raw]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function normalizeEpochMillis(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return null;
  }
  return value < 1e12 ? value * 1000 : value;
}

function matchPattern(pattern, value) {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) {
    return value.startsWith(pattern.slice(0, -1));
  }
  return pattern === value;
}

function capsAllow(available, required) {
  if (!Array.isArray(available) || available.length === 0) return false;
  return required.every(req =>
    available.some(cap =>
      cap &&
      typeof cap.resource === 'string' &&
      typeof cap.action === 'string' &&
      matchPattern(cap.resource, req.resource) &&
      matchPattern(cap.action, req.action)
    )
  );
}

function extractUcanStatement(message) {
  if (!message || typeof message !== 'string') return null;
  const lines = message.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('UCAN-AUTH')) {
      const jsonPart = trimmed.replace(/^UCAN-AUTH[:\\s]*/i, '');
      try {
        return JSON.parse(jsonPart);
      } catch {
        return null;
      }
    }
  }
  return null;
}

function verifyRootProof(root) {
  if (!root || root.type !== 'siwe' || !root.siwe) {
    throw new Error('Invalid root proof');
  }
  const { message, signature } = root.siwe;
  if (!message || !signature) {
    throw new Error('Missing SIWE message');
  }
  const recovered = ethers.verifyMessage(message, signature).toLowerCase();
  const iss = `did:pkh:eth:${recovered}`;
  if (root.iss && root.iss !== iss) {
    logWarn('UCAN root issuer mismatch', { rootIss: root.iss, recoveredIss: iss });
    throw new Error('Root issuer mismatch');
  }

  const statement = extractUcanStatement(message);
  if (!statement) {
    throw new Error('Missing UCAN statement');
  }

  const aud = statement.aud || root.aud;
  const cap = statement.cap || root.cap;
  const exp = normalizeEpochMillis(statement.exp ?? root.exp);
  const nbf = normalizeEpochMillis(statement.nbf ?? root.nbf);

  if (!aud || !Array.isArray(cap) || !exp) {
    logWarn('UCAN root claims invalid', { aud, exp, capCount: Array.isArray(cap) ? cap.length : 0 });
    throw new Error('Invalid root claims');
  }

  if (root.aud && root.aud !== aud) {
    logWarn('UCAN root audience mismatch', { rootAud: root.aud, aud });
    throw new Error('Root audience mismatch');
  }
  if (root.exp && normalizeEpochMillis(root.exp) !== exp) {
    logWarn('UCAN root expiry mismatch', { rootExp: root.exp, exp });
    throw new Error('Root expiry mismatch');
  }

  const nowMs = now();
  if (nbf && nowMs < nbf) {
    throw new Error('Root not active');
  }
  if (nowMs > exp) {
    throw new Error('Root expired');
  }

  logInfo('UCAN root verified', {
    iss,
    aud,
    exp,
    nbf,
    caps: summarizeCaps(cap),
  });
  return { iss, aud, cap, exp, nbf };
}

function decodeUcanToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid UCAN token');
  const header = decodeJsonSegment(parts[0]);
  const payload = decodeJsonSegment(parts[1]);
  const signature = base64UrlDecode(parts[2]);
  return { header, payload, signature, signingInput: `${parts[0]}.${parts[1]}` };
}

function verifyUcanJws(token) {
  const decoded = decodeUcanToken(token);
  if (decoded.header?.alg !== 'EdDSA') {
    throw new Error('Unsupported UCAN alg');
  }
  const rawKey = didKeyToPublicKey(decoded.payload?.iss || '');
  const publicKey = createEd25519PublicKey(rawKey);
  const ok = crypto.verify(null, Buffer.from(decoded.signingInput), publicKey, decoded.signature);
  if (!ok) {
    throw new Error('Invalid UCAN signature');
  }
  const exp = normalizeEpochMillis(decoded.payload.exp);
  const nbf = normalizeEpochMillis(decoded.payload.nbf);
  const nowMs = now();
  if (nbf && nowMs < nbf) {
    throw new Error('UCAN not active');
  }
  if (exp && nowMs > exp) {
    throw new Error('UCAN expired');
  }
  logInfo('UCAN JWS verified', {
    iss: decoded.payload?.iss,
    aud: decoded.payload?.aud,
    exp,
    nbf,
    caps: summarizeCaps(decoded.payload?.cap || []),
  });
  return { header: decoded.header, payload: decoded.payload, exp, nbf };
}

function verifyProofChain(currentDid, requiredCap, requiredExp, proofs) {
  if (!Array.isArray(proofs) || proofs.length === 0) {
    throw new Error('Missing UCAN proof chain');
  }
  logInfo('UCAN proof chain', {
    currentDid,
    requiredExp,
    proofs: proofs.length,
    requiredCaps: summarizeCaps(requiredCap),
  });
  const [first, ...rest] = proofs;
  if (typeof first === 'string') {
    const { payload, exp } = verifyUcanJws(first);
    if (payload.aud !== currentDid) {
      throw new Error(`UCAN audience mismatch expected=${currentDid} got=${payload.aud || ''}`);
    }
    const proofExp = normalizeEpochMillis(payload.exp) || exp;
    if (!capsAllow(payload.cap || [], requiredCap)) {
      throw new Error('UCAN capability denied');
    }
    if (proofExp && requiredExp && proofExp < requiredExp) {
      throw new Error('UCAN proof expired');
    }
    const nextProofs = Array.isArray(payload.prf) && payload.prf.length > 0 ? payload.prf : rest;
    return verifyProofChain(payload.iss, payload.cap || [], proofExp || requiredExp, nextProofs);
  }
  const root = verifyRootProof(first);
  if (root.aud !== currentDid) {
    throw new Error('Root audience mismatch');
  }
  if (!capsAllow(root.cap || [], requiredCap)) {
    throw new Error('Root capability denied');
  }
  if (requiredExp && root.exp < requiredExp) {
    throw new Error('Root expired');
  }
  return root;
}

function isUcanToken(token) {
  try {
    const [headerPart] = token.split('.');
    if (!headerPart) return false;
    const header = decodeJsonSegment(headerPart);
    return header?.typ === 'UCAN' || header?.alg === 'EdDSA';
  } catch {
    return false;
  }
}

function verifyUcanInvocation(token) {
  const { payload, exp } = verifyUcanJws(token);
  logInfo('UCAN invocation', {
    token: preview(token),
    iss: payload.iss,
    aud: payload.aud,
    exp,
    caps: summarizeCaps(payload.cap || []),
    proofs: Array.isArray(payload.prf) ? payload.prf.length : 0,
  });
  if (payload.aud !== UCAN_AUD) {
    throw new Error(`UCAN audience mismatch expected=${UCAN_AUD} got=${payload.aud || ''}`);
  }
  if (!capsAllow(payload.cap || [], [REQUIRED_UCAN_CAP])) {
    throw new Error('UCAN capability denied');
  }
  const root = verifyProofChain(payload.iss, payload.cap || [], exp, payload.prf || []);
  const address = root.iss.replace(/^did:pkh:eth:/, '');
  return { address, issuer: payload.iss };
}

function parseCookies(cookieHeader = '') {
  return cookieHeader.split(';').reduce((acc, part) => {
    const [key, ...rest] = part.trim().split('=');
    if (!key) return acc;
    acc[key] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function getCookie(req, name) {
  const header = req.headers?.cookie || '';
  const cookies = parseCookies(header);
  return cookies[name];
}

function setRefreshCookie(res, token, maxAgeMs) {
  res.cookie('refresh_token', token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    path: '/api/v1/public/auth',
    maxAge: maxAgeMs,
  });
}

function clearRefreshCookie(res) {
  res.cookie('refresh_token', '', {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    path: '/api/v1/public/auth',
    maxAge: 0,
  });
}

function signAccessToken(address, sessionId) {
  return jwt.sign(
    { address, typ: 'access', sid: sessionId },
    JWT_SECRET,
    { expiresIn: Math.floor(ACCESS_TTL_MS / 1000) }
  );
}

function signRefreshToken(address, refreshId) {
  return jwt.sign(
    { address, typ: 'refresh', jti: refreshId },
    JWT_SECRET,
    { expiresIn: Math.floor(REFRESH_TTL_MS / 1000) }
  );
}

function issueTokens(address, res) {
  const refreshId = crypto.randomUUID();
  const refreshExpiresAt = now() + REFRESH_TTL_MS;

  refreshStore.set(refreshId, {
    address,
    expiresAt: refreshExpiresAt,
  });

  const refreshToken = signRefreshToken(address, refreshId);
  setRefreshCookie(res, refreshToken, REFRESH_TTL_MS);

  const accessToken = signAccessToken(address, refreshId);
  const accessExpiresAt = now() + ACCESS_TTL_MS;

  return {
    accessToken,
    accessExpiresAt,
    refreshExpiresAt,
  };
}

function verifyAccessToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const [, token] = authHeader.split(' ');

  if (!token) {
    res.status(401).json(fail(401, 'Missing access token'));
    return;
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload?.typ !== 'access') {
      logWarn('Access token type mismatch', { typ: payload?.typ });
      res.status(401).json(fail(401, 'Invalid access token'));
      return;
    }
    req.user = payload;
    logInfo('Access token verified', { address: payload.address, sid: payload.sid });
    next();
  } catch (error) {
    logWarn('Access token verification failed', { error: error.message });
    res.status(401).json(fail(401, 'Invalid or expired access token'));
  }
}

app.post('/api/v1/public/auth/challenge', (req, res) => {
  const { address } = req.body || {};
  if (!address) {
    return res.status(400).json(fail(400, 'Missing address'));
  }
  logInfo('Auth challenge request', { address });

  const nonce = Math.random().toString(36).slice(2);
  const issuedAt = now();
  const expiresAt = issuedAt + 5 * 60 * 1000;
  const challenge = `Sign to login\n\nnonce: ${nonce}\nissuedAt: ${issuedAt}`;

  challenges.set(address.toLowerCase(), {
    challenge,
    issuedAt,
    expiresAt,
  });

  return res.json(
    ok({
      address,
      challenge,
      nonce,
      issuedAt,
      expiresAt,
    })
  );
});

app.post('/api/v1/public/auth/verify', (req, res) => {
  const { address, signature } = req.body || {};
  if (!address || !signature) {
    return res.status(400).json(fail(400, 'Missing address or signature'));
  }
  logInfo('Auth verify request', { address, signature: preview(signature) });

  const key = address.toLowerCase();
  const record = challenges.get(key);
  if (!record) {
    return res.status(400).json(fail(400, 'Challenge expired'));
  }

  if (now() > record.expiresAt) {
    challenges.delete(key);
    return res.status(400).json(fail(400, 'Challenge expired'));
  }

  try {
    const recovered = ethers.verifyMessage(record.challenge, signature);
    if (recovered.toLowerCase() !== key) {
      logWarn('Auth verify signature mismatch', { address: key, recovered });
      return res.status(401).json(fail(401, 'Invalid signature'));
    }

    challenges.delete(key);

    const { accessToken, accessExpiresAt, refreshExpiresAt } = issueTokens(key, res);

    return res.json(
      ok({
        address: key,
        token: accessToken,
        expiresAt: accessExpiresAt,
        refreshExpiresAt,
      })
    );
  } catch (error) {
    logError('Auth verify failed', { error: error.message });
    return res.status(500).json(fail(500, 'Verification failed'));
  }
});

app.post('/api/v1/public/auth/refresh', (req, res) => {
  const refreshToken = getCookie(req, 'refresh_token');
  if (!refreshToken) {
    return res.status(401).json(fail(401, 'Missing refresh token'));
  }
  logInfo('Auth refresh request', { token: preview(refreshToken) });

  let payload;
  try {
    payload = jwt.verify(refreshToken, JWT_SECRET);
  } catch (error) {
    logWarn('Refresh token verification failed', { error: error.message });
    clearRefreshCookie(res);
    return res.status(401).json(fail(401, 'Invalid refresh token'));
  }

  if (payload?.typ !== 'refresh' || !payload.jti) {
    logWarn('Refresh token type mismatch', { typ: payload?.typ, jti: payload?.jti });
    clearRefreshCookie(res);
    return res.status(401).json(fail(401, 'Invalid refresh token'));
  }

  const record = refreshStore.get(payload.jti);
  if (!record || record.address !== payload.address || now() > record.expiresAt) {
    logWarn('Refresh token expired', { address: payload.address, jti: payload.jti });
    refreshStore.delete(payload.jti);
    clearRefreshCookie(res);
    return res.status(401).json(fail(401, 'Refresh token expired'));
  }

  refreshStore.delete(payload.jti);
  const { accessToken, accessExpiresAt, refreshExpiresAt } = issueTokens(payload.address, res);

  return res.json(
    ok({
      address: payload.address,
      token: accessToken,
      expiresAt: accessExpiresAt,
      refreshExpiresAt,
    })
  );
});

app.post('/api/v1/public/auth/logout', (req, res) => {
  const refreshToken = getCookie(req, 'refresh_token');
  if (refreshToken) {
    try {
      const payload = jwt.verify(refreshToken, JWT_SECRET);
      if (payload?.jti) {
        refreshStore.delete(payload.jti);
      }
    } catch (error) {
      // ignore
    }
  }

  clearRefreshCookie(res);
  logInfo('Auth logout');
  return res.json(ok({ logout: true }));
});

app.get('/api/v1/public/profile', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const [, token] = authHeader.split(' ');

  if (!token) {
    res.status(401).json(fail(401, 'Missing access token'));
    return;
  }

  if (isUcanToken(token)) {
    try {
      const result = verifyUcanInvocation(token);
      logInfo('UCAN profile ok', { address: result.address, issuer: result.issuer });
      return res.json(
        ok({
          address: result.address,
          issuedAt: now(),
        })
      );
    } catch (error) {
      logWarn('UCAN profile failed', { error: error.message });
      res.status(401).json(fail(401, error.message || 'Invalid UCAN token'));
      return;
    }
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload?.typ !== 'access') {
      res.status(401).json(fail(401, 'Invalid access token'));
      return;
    }
    logInfo('JWT profile ok', { address: payload.address });
    return res.json(
      ok({
        address: payload.address,
        issuedAt: now(),
      })
    );
  } catch (error) {
    logWarn('JWT profile failed', { error: error.message });
    res.status(401).json(fail(401, 'Invalid or expired access token'));
  }
});

const frontendRoot = path.join(__dirname, '..', '..', 'frontend');
const distRoot = path.join(__dirname, '..', '..', '..', 'dist');
app.use('/dist', express.static(distRoot));
app.use('/', express.static(frontendRoot));

app.listen(PORT, () => {
  logInfo(`Auth server running at http://127.0.0.1:${PORT}`);
});
