import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseUcanAccountFromIssuer,
  resolveUcanAuthorization,
} from '../dist/web3-bs.esm.js';

const nowMs = 1_800_000_000_000;
const account = '0x5c7bf91c493126314bb821c123dee889ffca3932';
const capabilities = [
  { with: 'app:all:localhost-3020', can: 'invoke' },
  { with: 'app:all:localhost-3020', can: 'write' },
];

function root(overrides = {}) {
  return {
    type: 'siwe',
    iss: `did:pkh:eth:${account}`,
    aud: 'did:key:zSession',
    cap: capabilities,
    exp: nowMs + 60_000,
    siwe: {
      message:
        'localhost:3020 wants you to sign in with your Ethereum account:\n' +
        `${account}\n\n` +
        'UCAN-AUTH {"service_hosts":{"router":"127.0.0.1:3011","webdav":"127.0.0.1:6065"}}',
      signature: '0xsignature',
    },
    ...overrides,
  };
}

test('parseUcanAccountFromIssuer parses did:pkh Ethereum issuer', () => {
  assert.equal(
    parseUcanAccountFromIssuer(`did:pkh:eth:${account.toUpperCase()}`),
    account,
  );
  assert.equal(parseUcanAccountFromIssuer('did:key:zIssuer'), null);
});

test('resolveUcanAuthorization restores missing account from a valid root', async () => {
  const result = await resolveUcanAuthorization({
    root: root(),
    expectedCapabilities: capabilities,
    expectedServiceHosts: {
      router: '127.0.0.1:3011',
      webdav: '127.0.0.1:6065',
    },
    recoverAccountFromRoot: true,
    nowMs,
  });

  assert.equal(result.status, 'authorized');
  assert.equal(result.account, account);
  assert.equal(result.restoredAccount, true);
});

test('resolveUcanAuthorization can require an explicit current account', async () => {
  const result = await resolveUcanAuthorization({
    root: root(),
    expectedCapabilities: capabilities,
    recoverAccountFromRoot: false,
    nowMs,
  });

  assert.equal(result.status, 'unauthorized');
  assert.equal(result.reason, 'missing_account');
});

test('resolveUcanAuthorization rejects capability mismatch', async () => {
  const result = await resolveUcanAuthorization({
    root: root(),
    currentAccount: account,
    expectedCapabilities: [{ with: 'app:all:other', can: 'invoke' }],
    nowMs,
  });

  assert.equal(result.status, 'unauthorized');
  assert.equal(result.reason, 'capability_mismatch');
});

test('resolveUcanAuthorization rejects service host mismatch', async () => {
  const result = await resolveUcanAuthorization({
    root: root(),
    currentAccount: account,
    expectedCapabilities: capabilities,
    expectedServiceHosts: {
      router: 'llm.yeying.pub',
    },
    nowMs,
  });

  assert.equal(result.status, 'unauthorized');
  assert.equal(result.reason, 'service_host_mismatch');
});
