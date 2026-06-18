import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';

import {
  authCentralUcanFetch,
  authUcanFetch,
  classifyUcanAuthError,
  clearCentralSessionToken,
  createCentralSession,
  createUcanSession,
  getOrCreateInvocationUcan,
  getUcanTokenTiming,
  getCentralIssuerInfo,
  isUcanTokenFresh,
  issueCentralUcan,
} from '../dist/web3-bs.esm.js';

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8')
    .toString('base64url');
}

function unsignedUcan(payload) {
  return `${base64UrlJson({ alg: 'none', typ: 'UCAN' })}.${base64UrlJson(payload)}.signature`;
}

function parseJsonSafe(input) {
  if (!input) return {};
  try {
    return JSON.parse(input);
  } catch {
    return {};
  }
}

function readAuthHeader(req) {
  return String(req.headers.authorization || '').trim();
}

test('UCAN 有效期工具：支持 skew 判断与过期错误分类', () => {
  const nowMs = 1_800_000_000_000;
  const token = unsignedUcan({
    iss: 'did:key:zIssuer',
    aud: 'did:web:api.example.com',
    cap: [{ with: 'app:all:demo', can: 'invoke' }],
    exp: nowMs + 120_000,
    nbf: nowMs - 1_000,
    prf: [],
  });

  const timing = getUcanTokenTiming(token, { nowMs });
  assert.equal(timing.valid, true);
  assert.equal(timing.remainingMs, 120_000);
  assert.equal(isUcanTokenFresh(timing, { skewMs: 60_000 }), true);
  assert.equal(isUcanTokenFresh(timing, { skewMs: 180_000 }), false);

  const expired = classifyUcanAuthError({
    error: {
      message: 'UCAN expired (trace id: test)',
      type: 'one_api_error',
    },
  });
  assert.equal(expired.type, 'expired');
  assert.equal(expired.shouldRefresh, true);
  assert.equal(expired.retryable, true);
});

test('UCAN Invocation：足够新鲜时直接复用，避免无意义刷新', async () => {
  const nowMs = 1_800_000_000_000;
  const token = unsignedUcan({
    iss: 'did:key:zIssuer',
    aud: 'did:web:api.example.com',
    cap: [{ with: 'app:all:demo', can: 'invoke' }],
    exp: nowMs + 300_000,
    nbf: nowMs - 1_000,
    prf: [],
  });

  const resolved = await getOrCreateInvocationUcan({
    ucan: token,
    audience: 'did:web:api.example.com',
    capabilities: [{ with: 'app:all:demo', can: 'invoke' }],
    nowMs,
  });

  assert.equal(resolved, token);
});

test('UCAN fetch：遇到过期错误后自动刷新 Invocation 并重试一次', async () => {
  const authHeaders = [];
  const session = await createUcanSession({ id: 'retry-test-session', forceNew: true });
  let signatureCount = 0;
  session.signer = async () => `test-signature-${++signatureCount}`;
  let requestCount = 0;

  await withMockServer(async (req, rawBody, res) => {
    const authHeader = readAuthHeader(req);
    authHeaders.push(authHeader);

    requestCount += 1;
    if (requestCount === 1) {
      res.statusCode = 401;
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          error: {
            message: 'UCAN expired (trace id: retry-test)',
            code: 'UCAN_EXPIRED',
          },
        })
      );
      return;
    }

    assert.equal(rawBody, JSON.stringify({ hello: 'world' }));
    res.statusCode = 200;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: true }));
  }, async origin => {
    const response = await authUcanFetch(
      `${origin}/api/v1/public/protected`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ hello: 'world' }),
      },
      {
        issuer: session,
        audience: 'did:web:api.example.com',
        capabilities: [{ with: 'app:all:demo', can: 'invoke' }],
        proofs: ['root-proof'],
      }
    );

    assert.equal(response.status, 200);
    assert.equal(authHeaders.length, 2);
    assert.notEqual(authHeaders[0], authHeaders[1]);
    assert.equal(signatureCount, 2);
  });
});

async function withMockServer(handler, run) {
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString('utf8');
    });
    req.on('end', async () => {
      try {
        await handler(req, body, res);
      } catch (error) {
        res.statusCode = 500;
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify({
            code: 500,
            message: error instanceof Error ? error.message : String(error),
            data: null,
          })
        );
      }
    });
  });

  await new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', error => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });

  try {
    const address = server.address();
    if (!address || typeof address === 'string') {
      throw new Error('Failed to resolve mock server address');
    }
    const origin = `http://127.0.0.1:${address.port}`;
    await run(origin);
  } finally {
    await new Promise((resolve, reject) => {
      server.close(error => (error ? reject(error) : resolve()));
    });
  }
}

test('中心化接口：issuer/session/issue + authCentralUcanFetch', async () => {
  clearCentralSessionToken({ storeSessionToken: false });

  const callPaths = [];
  const expectedSession = 'session-token-001';
  const expectedUcan = 'ucan-token-001';

  await withMockServer(async (req, rawBody, res) => {
    const path = req.url || '';
    callPaths.push(`${req.method} ${path}`);

    if (req.method === 'GET' && path === '/api/v1/public/auth/central/issuer') {
      assert.equal(readAuthHeader(req), 'Bearer jwt-access-token');
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          code: 0,
          message: 'ok',
          data: {
            enabled: true,
            mode: 'issue',
            ready: true,
            issuerDid: 'did:key:zIssuer',
            defaultAudience: 'did:web:localhost:8100',
            defaultCapabilities: [{ with: 'app:all:mobile-demo', can: 'read' }],
          },
        })
      );
      return;
    }

    if (req.method === 'POST' && path === '/api/v1/public/auth/central/session') {
      assert.equal(readAuthHeader(req), 'Bearer jwt-access-token');
      const payload = parseJsonSafe(rawBody);
      assert.equal(payload.subject, 'mobile-user-001');
      assert.equal(payload.sessionTtlMs, 300000);
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          code: 0,
          message: 'ok',
          data: {
            subject: 'mobile-user-001',
            issuerDid: 'did:key:zIssuer',
            sessionToken: expectedSession,
            expiresAt: Date.now() + 300000,
          },
        })
      );
      return;
    }

    if (req.method === 'POST' && path === '/api/v1/public/auth/central/issue') {
      assert.equal(readAuthHeader(req), `Bearer ${expectedSession}`);
      const payload = parseJsonSafe(rawBody);
      assert.equal(payload.audience, 'did:web:localhost:8100');
      assert.equal(Array.isArray(payload.capabilities), true);
      assert.equal(payload.capabilities.length, 1);
      assert.equal(payload.capabilities[0].with, 'app:all:mobile-demo');
      assert.equal(payload.capabilities[0].can, 'read');
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          code: 0,
          message: 'ok',
          data: {
            ucan: expectedUcan,
            issuerDid: 'did:key:zIssuer',
            subject: 'mobile-user-001',
            audience: 'did:web:localhost:8100',
            capabilities: [{ with: 'app:all:mobile-demo', can: 'read' }],
            exp: Math.floor(Date.now() / 1000) + 600,
            nbf: Math.floor(Date.now() / 1000),
            iat: Math.floor(Date.now() / 1000),
          },
        })
      );
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/public/profile/me') {
      assert.equal(readAuthHeader(req), `Bearer ${expectedUcan}`);
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          code: 0,
          message: 'ok',
          data: {
            authType: 'ucan',
            source: 'central',
          },
        })
      );
      return;
    }

    res.statusCode = 404;
    res.end();
  }, async origin => {
    const baseUrl = `${origin}/api/v1/public/auth/central`;

    const issuer = await getCentralIssuerInfo({
      baseUrl,
      accessToken: 'jwt-access-token',
      storeSessionToken: false,
    });
    assert.equal(issuer.issuerDid, 'did:key:zIssuer');

    const session = await createCentralSession({
      baseUrl,
      accessToken: 'jwt-access-token',
      subject: 'mobile-user-001',
      sessionTtlMs: 300000,
      storeSessionToken: false,
    });
    assert.equal(session.sessionToken, expectedSession);

    const issued = await issueCentralUcan({
      baseUrl,
      sessionToken: session.sessionToken,
      audience: 'did:web:localhost:8100',
      capabilities: [{ with: 'app:all:mobile-demo', can: 'read' }],
      storeSessionToken: false,
    });
    assert.equal(issued.ucan, expectedUcan);

    const response = await authCentralUcanFetch(
      `${origin}/api/v1/public/profile/me`,
      { method: 'GET' },
      { ucan: issued.ucan, storeSessionToken: false }
    );
    assert.equal(response.status, 200);

    assert.deepEqual(callPaths, [
      'GET /api/v1/public/auth/central/issuer',
      'POST /api/v1/public/auth/central/session',
      'POST /api/v1/public/auth/central/issue',
      'GET /api/v1/public/profile/me',
    ]);
  });
});

test('中心化接口：authCentralUcanFetch 可自动 session+issue', async () => {
  clearCentralSessionToken({ storeSessionToken: false });

  const callPaths = [];
  const expectedSession = 'session-token-auto';
  const expectedUcan = 'ucan-token-auto';

  await withMockServer(async (req, rawBody, res) => {
    const path = req.url || '';
    callPaths.push(`${req.method} ${path}`);

    if (req.method === 'POST' && path === '/api/v1/public/auth/central/session') {
      assert.equal(readAuthHeader(req), 'Bearer jwt-token-auto');
      const payload = parseJsonSafe(rawBody);
      assert.equal(payload.subject, '0xabc0000000000000000000000000000000000000');
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          code: 0,
          message: 'ok',
          data: {
            subject: payload.subject,
            sessionToken: expectedSession,
          },
        })
      );
      return;
    }

    if (req.method === 'POST' && path === '/api/v1/public/auth/central/issue') {
      assert.equal(readAuthHeader(req), `Bearer ${expectedSession}`);
      const payload = parseJsonSafe(rawBody);
      assert.equal(payload.audience, 'did:web:localhost:8100');
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          code: 0,
          message: 'ok',
          data: {
            ucan: expectedUcan,
          },
        })
      );
      return;
    }

    if (req.method === 'GET' && path === '/api/v1/public/profile/me') {
      assert.equal(readAuthHeader(req), `Bearer ${expectedUcan}`);
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ code: 0, message: 'ok', data: { ok: true } }));
      return;
    }

    res.statusCode = 404;
    res.end();
  }, async origin => {
    const response = await authCentralUcanFetch(
      `${origin}/api/v1/public/profile/me`,
      { method: 'GET' },
      {
        baseUrl: `${origin}/api/v1/public/auth/central`,
        subject: '0xabc0000000000000000000000000000000000000',
        accessToken: 'jwt-token-auto',
        audience: 'did:web:localhost:8100',
        capabilities: [{ with: 'app:all:mobile-demo', can: 'read' }],
        storeSessionToken: false,
      }
    );
    assert.equal(response.status, 200);

    assert.deepEqual(callPaths, [
      'POST /api/v1/public/auth/central/session',
      'POST /api/v1/public/auth/central/issue',
      'GET /api/v1/public/profile/me',
    ]);
  });
});
