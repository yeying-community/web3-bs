/**
 * encrypt.ts SDK API 单测（mock provider，无真 wallet）
 * 运行：npm run build && node scripts/run-node-tests.mjs
 *
 * 覆盖：encrypt/decrypt/getSupportedCipherSuites 的 RPC 拼接 + 错误分类。
 * 算法正确性在 wallet 仓的 tests/crypto-suites.test.mjs 验证；这里只测 SDK
 * 层与 provider 的契约。
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  encrypt,
  decrypt,
  getSupportedCipherSuites,
  CipherError,
  isUserRejectedWalletAction,
  bytesToBase64,
  base64ToBytes
} from '../dist/web3-bs.esm.js';

// ==================== 工具函数 ====================

test('bytesToBase64 / base64ToBytes 双向', () => {
  const data = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
  const b64 = bytesToBase64(data);
  const back = base64ToBytes(b64);
  assert.equal(back.length, data.length);
  for (let i = 0; i < data.length; i += 1) assert.equal(back[i], data[i]);
});

// ==================== Mock provider ====================

function makeProvider(handler) {
  return {
    request: async ({ method, params }) => handler(method, params)
  };
}

const SUITE_LIST = [
  { name: 'aes-256-gcm', description: 'AES-256-GCM', mode: 'symmetric' },
  { name: 'sm4-cbc-hmac-sm3', description: 'SM4-CBC + HMAC-SM3', mode: 'symmetric' },
  { name: 'sha-256', description: 'SHA-256', mode: 'hash' },
  { name: 'sm3', description: 'SM3', mode: 'hash' }
];

// ==================== getSupportedCipherSuites ====================

test('getSupportedCipherSuites：透传 provider 响应', async () => {
  const provider = makeProvider(async (method) => {
    assert.equal(method, 'yeying_getCipherSuites');
    return { suites: SUITE_LIST };
  });
  const suites = await getSupportedCipherSuites({ provider });
  assert.equal(suites.length, 4);
  assert.equal(suites[0].name, 'aes-256-gcm');
  assert.equal(suites[2].mode, 'hash');
});

test('getSupportedCipherSuites：响应格式错误抛错', async () => {
  const provider = makeProvider(async () => ({ wrong: 'shape' }));
  await assert.rejects(
    () => getSupportedCipherSuites({ provider }),
    (err) => /Invalid getCipherSuites response/.test(err.message)
  );
});

// ==================== encrypt ====================

test('encrypt：透传 params + 接收 ciphertext', async () => {
  const provider = makeProvider(async (method, params) => {
    assert.equal(method, 'yeying_encrypt');
    const opts = Array.isArray(params) ? params[0] : params;
    assert.equal(opts.data, 'secret-data');
    assert.equal(opts.password, 'p');
    assert.equal(opts.passwordSource, 'manual');
    assert.equal(opts.passwordContext, '/personal/secure');
    assert.equal(opts.suite, 'aes-256-gcm');
    return { ciphertext: 'v1:aes-256-gcm:...', suite: 'aes-256-gcm' };
  });
  const ct = await encrypt({
    data: 'secret-data',
    password: 'p',
    passwordSource: 'manual',
    passwordContext: '/personal/secure',
    suite: 'aes-256-gcm',
    provider
  });
  assert.equal(ct, 'v1:aes-256-gcm:...');
});

test('encrypt：支持钱包派生密码参数，无需传 password', async () => {
  const provider = makeProvider(async (method, params) => {
    assert.equal(method, 'yeying_encrypt');
    const opts = Array.isArray(params) ? params[0] : params;
    assert.equal(opts.data, 'wallet-secret');
    assert.equal(opts.password, undefined);
    assert.equal(opts.passwordSource, 'wallet');
    assert.equal(opts.passwordContext, '/personal/wallet-only');
    return { ciphertext: 'v1:aes-256-gcm:wallet' };
  });
  const ct = await encrypt({
    data: 'wallet-secret',
    passwordSource: 'wallet',
    passwordContext: '/personal/wallet-only',
    provider
  });
  assert.equal(ct, 'v1:aes-256-gcm:wallet');
});

test('encrypt：不传 suite 时 provider 收到 undefined（钱包默认 aes-256-gcm）', async () => {
  let received;
  const provider = makeProvider(async (_method, params) => {
    received = Array.isArray(params) ? params[0] : params;
    return { ciphertext: 'v1:...' };
  });
  await encrypt({ data: 'x', password: 'p', provider });
  assert.equal(received.suite, undefined);
});

test('encrypt：Uint8Array 数据也能透传', async () => {
  let received;
  const provider = makeProvider(async (_m, params) => {
    received = Array.isArray(params) ? params[0] : params;
    return { ciphertext: 'v1:...' };
  });
  const data = new Uint8Array([1, 2, 3, 4]);
  await encrypt({ data, password: 'p', provider });
  assert.ok(received.data instanceof Uint8Array);
  assert.equal(received.data.length, 4);
});

test('encrypt：响应缺 ciphertext 抛错', async () => {
  const provider = makeProvider(async () => ({ suite: 'x' }));
  await assert.rejects(
    () => encrypt({ data: 'x', password: 'p', provider }),
    (err) => /Invalid encrypt response/.test(err.message)
  );
});

// ==================== decrypt ====================

test('decrypt：base64 plaintext 还原为 Uint8Array', async () => {
  const original = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
  const provider = makeProvider(async (method, params) => {
    assert.equal(method, 'yeying_decrypt');
    const opts = Array.isArray(params) ? params[0] : params;
    assert.equal(opts.ciphertext, 'v1:...');
    assert.equal(opts.password, 'p');
    assert.equal(opts.passwordSource, 'wallet+password');
    assert.equal(opts.passwordContext, '/personal/secure');
    return { plaintext: bytesToBase64(original), encoding: 'base64' };
  });
  const pt = await decrypt({
    ciphertext: 'v1:...',
    password: 'p',
    passwordSource: 'wallet+password',
    passwordContext: '/personal/secure',
    provider
  });
  assert.ok(pt instanceof Uint8Array);
  assert.equal(pt.length, 5);
  for (let i = 0; i < 5; i += 1) assert.equal(pt[i], original[i]);
});

test('decrypt：encoding 字段非 base64 抛错', async () => {
  const provider = makeProvider(async () => ({ plaintext: 'abc', encoding: 'hex' }));
  await assert.rejects(
    () => decrypt({ ciphertext: 'v1:...', password: 'p', provider }),
    (err) => /Unsupported plaintext encoding/.test(err.message)
  );
});

test('decrypt：响应缺 plaintext 抛错', async () => {
  const provider = makeProvider(async () => ({ encoding: 'base64' }));
  await assert.rejects(
    () => decrypt({ ciphertext: 'v1:...', password: 'p', provider }),
    (err) => /Invalid decrypt response/.test(err.message)
  );
});

// ==================== 错误分类 ====================

test('provider 抛 user-rejected（code 4001）→ CipherError type=userRejected', async () => {
  const provider = makeProvider(async () => {
    const e = new Error('User rejected');
    (e).code = 4001;
    throw e;
  });
  let caught;
  try {
    await encrypt({ data: 'x', password: 'p', provider });
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof CipherError);
  assert.equal(caught.type, 'userRejected');
  assert.equal(caught.code, 4001);
  assert.ok(isUserRejectedWalletAction(caught));
});

test('provider 抛 disconnected（code 4900）→ CipherError type=disconnected', async () => {
  const provider = makeProvider(async () => {
    const e = new Error('disconnected');
    (e).code = 4900;
    throw e;
  });
  let caught;
  try {
    await getSupportedCipherSuites({ provider });
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof CipherError);
  assert.equal(caught.type, 'disconnected');
  assert.equal(isUserRejectedWalletAction(caught), false);
});

test('provider 抛未知错误 → CipherError type=unknown', async () => {
  const provider = makeProvider(async () => {
    throw new Error('something weird');
  });
  let caught;
  try {
    await decrypt({ ciphertext: 'v1:...', password: 'p', provider });
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof CipherError);
  assert.equal(caught.type, 'unknown');
  assert.equal(caught.code, null);
  assert.ok(caught.originalError instanceof Error);
});

// ==================== provider 选项透传 ====================

test('不传 provider 选项时调用 requireProvider（缺 provider 抛 No injected）', async () => {
  // 模拟 requireProvider 失败：清空 window.ethereum
  const origWindow = globalThis.window;
  // @ts-ignore - 测试需要无 provider 的环境
  delete globalThis.window;
  try {
    await assert.rejects(
      () => encrypt({ data: 'x', password: 'p' }),
      (err) => /No injected wallet provider/.test(err.message)
    );
  } finally {
    globalThis.window = origWindow;
  }
});
