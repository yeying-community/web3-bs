import assert from 'node:assert/strict';

import {
  authCentralUcanFetch,
  createCentralSession,
  createInvocationUcan,
  createRootUcan,
  createUcanSession,
  initWebDavStorage,
  issueCentralUcan,
} from '../dist/web3-bs.esm.js';

const TEST_ADDRESS = '0x1111111111111111111111111111111111111111';

function decodeBase64Url(input) {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  return Buffer.from(padded, 'base64').toString('utf8');
}

function decodePayload(token) {
  const parts = token.split('.');
  assert.equal(parts.length, 3, 'UCAN token must have 3 parts');
  return JSON.parse(decodeBase64Url(parts[1]));
}

function makeWalletProvider() {
  return {
    async request({ method }) {
      if (method === 'yeying_ucan_session') {
        return {
          id: 'wallet-session',
          did: 'did:key:zWalletSession',
          createdAt: Date.now(),
          expiresAt: Date.now() + 60 * 60 * 1000,
        };
      }
      if (method === 'yeying_ucan_sign') {
        return { signature: 'walletSignature' };
      }
      if (method === 'eth_accounts' || method === 'eth_requestAccounts') {
        return [TEST_ADDRESS];
      }
      if (method === 'eth_chainId') {
        return '0x1';
      }
      if (method === 'personal_sign') {
        return '0xwallet_personal_sign';
      }
      throw new Error(`Unsupported wallet method: ${method}`);
    },
  };
}

function makeLocalFallbackProvider() {
  return {
    async request({ method }) {
      if (method === 'yeying_ucan_session' || method === 'yeying_ucan_sign') {
        throw new Error(`${method} not supported`);
      }
      if (method === 'eth_accounts' || method === 'eth_requestAccounts') {
        return [TEST_ADDRESS];
      }
      if (method === 'eth_chainId') {
        return '0x1';
      }
      if (method === 'personal_sign') {
        return '0xlocal_personal_sign';
      }
      throw new Error(`Unsupported local method: ${method}`);
    },
  };
}

async function checkWalletManagedPath() {
  const provider = makeWalletProvider();
  const session = await createUcanSession({
    id: 'wallet-test-session',
    provider,
    forceNew: true,
  });
  assert.equal(session.source, 'wallet');
  assert.equal(session.did, 'did:key:zWalletSession');
  assert.equal(typeof session.signer, 'function');

  const root = await createRootUcan({
    provider,
    session,
    capabilities: [{ with: 'profile', can: 'read' }],
    domain: '127.0.0.1:8001',
    uri: 'http://127.0.0.1:8001/examples/frontend/dapp.html',
  });
  assert.equal(root.aud, session.did);
  assert.equal(root.type, 'siwe');

  const invocation = await createInvocationUcan({
    issuer: session,
    audience: 'did:web:127.0.0.1:3203',
    capabilities: [{ with: 'profile', can: 'read' }],
    proofs: [root],
  });
  const payload = decodePayload(invocation);
  assert.equal(payload.iss, session.did);
  assert.equal(payload.aud, 'did:web:127.0.0.1:3203');
  assert.equal(payload.cap[0].with, 'profile');
  assert.equal(payload.cap[0].can, 'read');

  return {
    sessionSource: session.source,
    rootAudience: root.aud,
    invocationAudience: payload.aud,
  };
}

async function checkLocalFallbackPath() {
  const provider = makeLocalFallbackProvider();
  const session = await createUcanSession({
    id: 'local-test-session',
    provider,
    forceNew: true,
  });
  assert.equal(session.source, 'local');
  assert.equal(typeof session.privateKey, 'object');

  const root = await createRootUcan({
    provider,
    session,
    capabilities: [{ with: 'profile', can: 'read' }],
    domain: '127.0.0.1:8001',
    uri: 'http://127.0.0.1:8001/examples/frontend/dapp.html',
  });
  assert.equal(root.aud, session.did);

  const invocation = await createInvocationUcan({
    issuer: session,
    audience: 'did:web:127.0.0.1:3204',
    capabilities: [{ with: 'profile', can: 'read' }],
    proofs: [root],
  });
  const payload = decodePayload(invocation);
  assert.equal(payload.iss, session.did);
  assert.equal(payload.aud, 'did:web:127.0.0.1:3204');

  const requests = [];
  const fetcher = async (input, init = {}) => {
    const headers = new Headers(init.headers || {});
    requests.push({
      url: String(input),
      method: init.method || 'GET',
      authorization: headers.get('Authorization'),
    });
    if ((init.method || 'GET') === 'MKCOL') {
      return new Response('', { status: 201, statusText: 'Created' });
    }
    return new Response('{}', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  const storage = await initWebDavStorage({
    baseUrl: 'http://127.0.0.1:6065',
    prefix: '/dav',
    audience: 'did:web:127.0.0.1:6065',
    appId: '127.0.0.1:8001',
    capabilities: [{ with: 'app:all:127.0.0.1:8001', can: 'write' }],
    provider,
    session,
    root,
    fetcher,
  });

  assert.equal(storage.appDir, '/apps/127.0.0.1-8001');
  assert.ok(storage.token.length > 20);
  assert.ok(requests.some(entry => entry.method === 'MKCOL'));
  assert.ok(requests.some(entry => (entry.authorization || '').startsWith('Bearer ')));

  return {
    sessionSource: session.source,
    rootAudience: root.aud,
    invocationAudience: payload.aud,
    webdavAppDir: storage.appDir,
    requestCount: requests.length,
  };
}

function checkCentralApiExports() {
  assert.equal(typeof createCentralSession, 'function');
  assert.equal(typeof issueCentralUcan, 'function');
  assert.equal(typeof authCentralUcanFetch, 'function');
  return {
    createCentralSession: true,
    issueCentralUcan: true,
    authCentralUcanFetch: true,
  };
}

async function main() {
  const walletManaged = await checkWalletManagedPath();
  const localFallback = await checkLocalFallbackPath();
  const centralExports = checkCentralApiExports();

  const result = {
    ok: true,
    walletManaged,
    localFallback,
    centralExports,
  };
  console.log(JSON.stringify(result, null, 2));
}

main().catch(error => {
  console.error('[ucan-capability-check] failed');
  console.error(error);
  process.exit(1);
});
