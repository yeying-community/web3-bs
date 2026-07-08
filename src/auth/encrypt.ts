/**
 * 加密/解密 SDK API
 *
 * 调用钱包插件的 `yeying_encrypt` / `yeying_decrypt` / `yeying_getCipherSuites`
 * EIP-1193 自定义方法。命名安全套件 + 静默执行 + 站点授权模型同 UCAN。
 *
 * 默认数据密码（password 参数）由 DApp 自行管理与钱包密码独立；
 * 也可通过 passwordSource 请求钱包插件在钱包内部派生加密密码。
 * plaintext 走 base64 字符串跨 message 边界传输。
 */

import { requireProvider, classifyWalletError, isUserRejectedWalletAction } from './provider';
import type { Eip1193Provider } from './types';

export interface CipherSuiteInfo {
  name: string;
  description: string;
  mode: 'hash' | 'symmetric';
}

export type CipherPasswordSource = 'manual' | 'wallet' | 'wallet+password';

export interface EncryptOptions {
  data: string | Uint8Array;
  password?: string;
  passwordSource?: CipherPasswordSource;
  passwordContext?: string;
  suite?: string;
  provider?: Eip1193Provider;
}

export interface DecryptOptions {
  ciphertext: string;
  password?: string;
  passwordSource?: CipherPasswordSource;
  passwordContext?: string;
  provider?: Eip1193Provider;
}

export interface GetCipherSuitesOptions {
  provider?: Eip1193Provider;
}

export class CipherError extends Error {
  readonly type: 'userRejected' | 'disconnected' | 'timeout' | 'notFound' | 'unknown';
  readonly code: number | null;
  readonly originalError: unknown;

  constructor(message: string, type: CipherError['type'], code: number | null, originalError: unknown) {
    super(message);
    this.name = 'CipherError';
    this.type = type;
    this.code = code;
    this.originalError = originalError;
  }
}

function wrapCipherError(err: unknown): never {
  const info = classifyWalletError(err);
  throw new CipherError(info.message, info.type as CipherError['type'], info.code, err);
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * 用指定/默认套件加密数据
 * @returns v1 格式密文 base64 字符串
 */
export async function encrypt(options: EncryptOptions): Promise<string> {
  const provider = options.provider || (await requireProvider());
  try {
    const result = await provider.request({
      method: 'yeying_encrypt',
      params: [{
        data: options.data,
        password: options.password,
        passwordSource: options.passwordSource,
        passwordContext: options.passwordContext,
        suite: options.suite
      }]
    });
    if (!result || typeof result !== 'object' || typeof (result as any).ciphertext !== 'string') {
      throw new Error('Invalid encrypt response: missing ciphertext');
    }
    return (result as { ciphertext: string }).ciphertext;
  } catch (err) {
    wrapCipherError(err);
  }
}

/**
 * 解密 v1 格式密文
 * @returns 明文 Uint8Array
 */
export async function decrypt(options: DecryptOptions): Promise<Uint8Array> {
  const provider = options.provider || (await requireProvider());
  try {
    const result = await provider.request({
      method: 'yeying_decrypt',
      params: [{
        ciphertext: options.ciphertext,
        password: options.password,
        passwordSource: options.passwordSource,
        passwordContext: options.passwordContext
      }]
    });
    if (!result || typeof result !== 'object' || typeof (result as any).plaintext !== 'string') {
      throw new Error('Invalid decrypt response: missing plaintext');
    }
    const { plaintext, encoding } = result as { plaintext: string; encoding?: string };
    if (encoding && encoding !== 'base64') {
      throw new Error(`Unsupported plaintext encoding: ${encoding}`);
    }
    return base64ToBytes(plaintext);
  } catch (err) {
    wrapCipherError(err);
  }
}

/**
 * 列出可用的命名安全套件
 */
export async function getSupportedCipherSuites(
  options: GetCipherSuitesOptions = {}
): Promise<CipherSuiteInfo[]> {
  const provider = options.provider || (await requireProvider());
  try {
    const result = await provider.request({
      method: 'yeying_getCipherSuites',
      params: []
    });
    if (!result || typeof result !== 'object' || !Array.isArray((result as any).suites)) {
      throw new Error('Invalid getCipherSuites response: missing suites array');
    }
    return (result as { suites: CipherSuiteInfo[] }).suites;
  } catch (err) {
    wrapCipherError(err);
  }
}

// 内部 helper 导出（便于测试）
export { bytesToBase64, base64ToBytes };

// 重导出常用工具，避免用户单独 import
export { isUserRejectedWalletAction };
