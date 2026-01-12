const express = require('express');
const cors = require('cors');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

const PORT = Number(process.env.PORT || 4001);
const JWT_SECRET = process.env.JWT_SECRET || 'replace-this-in-production';
const ACCESS_TTL_MS = Number(process.env.ACCESS_TTL_MS || 15 * 60 * 1000);
const REFRESH_TTL_MS = Number(process.env.REFRESH_TTL_MS || 7 * 24 * 60 * 60 * 1000);
const COOKIE_SAMESITE = (process.env.COOKIE_SAMESITE || 'lax').toLowerCase();
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || '').toLowerCase() === 'true';

const allowedOrigins = new Set(
  (process.env.CORS_ORIGINS || [
    `http://localhost:${PORT}`,
    `http://127.0.0.1:${PORT}`,
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    'http://localhost:8001',
    'http://127.0.0.1:8001',
  ].join(',')).split(',').map(origin => origin.trim()).filter(Boolean)
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

const challenges = new Map();
const refreshStore = new Map();

function now() {
  return Date.now();
}

function ok(data) {
  return { code: 0, message: 'ok', data, timestamp: now() };
}

function fail(code, message) {
  return { code, message, data: null, timestamp: now() };
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
      res.status(401).json(fail(401, 'Invalid access token'));
      return;
    }
    req.user = payload;
    next();
  } catch (error) {
    res.status(401).json(fail(401, 'Invalid or expired access token'));
  }
}

app.post('/api/v1/public/auth/challenge', (req, res) => {
  const { address } = req.body || {};
  if (!address) {
    return res.status(400).json(fail(400, 'Missing address'));
  }

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
    return res.status(500).json(fail(500, 'Verification failed'));
  }
});

app.post('/api/v1/public/auth/refresh', (req, res) => {
  const refreshToken = getCookie(req, 'refresh_token');
  if (!refreshToken) {
    return res.status(401).json(fail(401, 'Missing refresh token'));
  }

  let payload;
  try {
    payload = jwt.verify(refreshToken, JWT_SECRET);
  } catch (error) {
    clearRefreshCookie(res);
    return res.status(401).json(fail(401, 'Invalid refresh token'));
  }

  if (payload?.typ !== 'refresh' || !payload.jti) {
    clearRefreshCookie(res);
    return res.status(401).json(fail(401, 'Invalid refresh token'));
  }

  const record = refreshStore.get(payload.jti);
  if (!record || record.address !== payload.address || now() > record.expiresAt) {
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
  return res.json(ok({ logout: true }));
});

app.get('/api/v1/private/profile', verifyAccessToken, (req, res) => {
  return res.json(
    ok({
      address: req.user.address,
      issuedAt: now(),
    })
  );
});

const frontendRoot = path.join(__dirname, '..', '..', 'frontend');
const distRoot = path.join(__dirname, '..', '..', '..', 'dist');
app.use('/dist', express.static(distRoot));
app.use('/', express.static(frontendRoot));

app.listen(PORT, () => {
  console.log(`Auth server running at http://localhost:${PORT}`);
});
