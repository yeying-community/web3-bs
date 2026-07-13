import test from 'node:test';
import assert from 'node:assert/strict';

import {
  connectAndGetWalletProfile,
  getGrantedProfileFields,
  getWalletProfile,
  getWalletProfilePermission,
  requestWalletProfilePermission,
  revokeWalletProfilePermission,
} from '../dist/web3-bs.esm.js';

function permission(fields) {
  return {
    parentCapability: 'yeying_profile',
    caveats: [{ type: 'restrictProfileFields', value: fields }],
  };
}

function createProvider(handler) {
  const calls = [];
  return {
    calls,
    async request(request) {
      calls.push(request);
      return handler(request, calls);
    },
  };
}

test('profile permission fields are normalized from caveats', () => {
  assert.deepEqual(getGrantedProfileFields(permission(['username', 'email', 'username'])), [
    'username',
    'email',
  ]);
  assert.deepEqual(getGrantedProfileFields({
    parentCapability: 'yeying_profile',
    caveats: [{ value: { fields: ['email'] } }],
  }), ['email']);
});

test('requestWalletProfilePermission requests explicit fields', async () => {
  const provider = createProvider(request => {
    assert.equal(request.method, 'wallet_requestPermissions');
    assert.deepEqual(request.params, [{ yeying_profile: { fields: ['username', 'email'] } }]);
    return [permission(['username', 'email'])];
  });
  const result = await requestWalletProfilePermission({
    provider,
    fields: ['username', 'email', 'username'],
  });
  assert.deepEqual(getGrantedProfileFields(result), ['username', 'email']);
});

test('getWalletProfile returns only requested string fields', async () => {
  const provider = createProvider(() => ({
    address: '0xabc',
    chainId: '0x1',
    profile: { username: 'alice', email: 'alice@example.com', ignored: true },
  }));
  assert.deepEqual(await getWalletProfile({ provider, fields: ['username'] }), {
    address: '0xabc',
    chainId: '0x1',
    profile: { username: 'alice' },
  });
});

test('connectAndGetWalletProfile requests only missing permissions', async () => {
  const provider = createProvider(request => {
    if (request.method === 'eth_requestAccounts') return ['0xabc'];
    if (request.method === 'wallet_getPermissions') return [permission(['username'])];
    if (request.method === 'wallet_requestPermissions') {
      assert.deepEqual(request.params, [{ yeying_profile: { fields: ['email'] } }]);
      return [permission(['username', 'email'])];
    }
    if (request.method === 'yeying_getProfile') {
      return {
        address: '0xabc',
        chainId: '0x1',
        profile: { username: 'alice', email: 'alice@example.com' },
      };
    }
    throw new Error(`Unexpected method: ${request.method}`);
  });

  const result = await connectAndGetWalletProfile({
    provider,
    fields: ['username', 'email'],
  });
  assert.equal(result.profile.email, 'alice@example.com');
  assert.deepEqual(provider.calls.map(call => call.method), [
    'eth_requestAccounts',
    'wallet_getPermissions',
    'wallet_requestPermissions',
    'yeying_getProfile',
  ]);
});

test('permission query and revoke use standard wallet permission RPCs', async () => {
  const provider = createProvider(request => {
    if (request.method === 'wallet_getPermissions') return [permission(['email'])];
    if (request.method === 'wallet_revokePermissions') return [permission(['email'])];
    throw new Error('Unexpected method');
  });
  assert.deepEqual(getGrantedProfileFields(await getWalletProfilePermission(provider)), ['email']);
  await revokeWalletProfilePermission(provider);
  assert.deepEqual(provider.calls[1], {
    method: 'wallet_revokePermissions',
    params: [{ yeying_profile: {} }],
  });
});

test('unsupported profile fields fail before calling the wallet', async () => {
  const provider = createProvider(() => null);
  await assert.rejects(
    getWalletProfile({ provider, fields: ['phone'] }),
    /Unsupported wallet profile field/
  );
  assert.equal(provider.calls.length, 0);
});
