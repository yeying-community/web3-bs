import { requireProvider } from './provider';
import type { Eip1193Provider } from './types';

export type WalletProfileField = 'username' | 'email';

export type WalletProfile = Partial<Record<WalletProfileField, string>>;

export type WalletProfilePermission = {
  parentCapability: 'yeying_profile';
  caveats?: Array<{
    type?: string;
    value?: WalletProfileField[] | {
      fields?: WalletProfileField[];
      [key: string]: unknown;
    };
    [key: string]: unknown;
  }>;
  date?: number;
  [key: string]: unknown;
};

export type WalletProfileResult = {
  address: string;
  chainId: string | null;
  profile: WalletProfile;
};

export type WalletProfileOptions = {
  provider?: Eip1193Provider;
  fields: WalletProfileField[];
};

export type ConnectWalletProfileOptions = WalletProfileOptions & {
  requestPermission?: boolean;
};

const SUPPORTED_FIELDS = new Set<WalletProfileField>(['username', 'email']);

function normalizeFields(fields: WalletProfileField[]): WalletProfileField[] {
  if (!Array.isArray(fields) || fields.length === 0) {
    throw new Error('Profile fields must contain username and/or email');
  }
  const normalized = Array.from(new Set(fields.map(field => String(field) as WalletProfileField)));
  if (normalized.some(field => !SUPPORTED_FIELDS.has(field))) {
    throw new Error('Unsupported wallet profile field');
  }
  return normalized;
}

function parsePermission(value: unknown): WalletProfilePermission | null {
  if (!value || typeof value !== 'object') return null;
  const permission = value as WalletProfilePermission;
  return permission.parentCapability === 'yeying_profile' ? permission : null;
}

export function getGrantedProfileFields(permission: WalletProfilePermission | null): WalletProfileField[] {
  if (!permission || !Array.isArray(permission.caveats)) return [];
  const fields = permission.caveats.flatMap(caveat => {
    if (Array.isArray(caveat?.value)) return caveat.value;
    return Array.isArray(caveat?.value?.fields) ? caveat.value.fields : [];
  });
  return Array.from(new Set(fields.filter(field => SUPPORTED_FIELDS.has(field))));
}

export async function getWalletProfilePermission(
  provider?: Eip1193Provider
): Promise<WalletProfilePermission | null> {
  const target = provider || (await requireProvider());
  const permissions = await target.request({ method: 'wallet_getPermissions' });
  if (!Array.isArray(permissions)) return null;
  return permissions.map(parsePermission).find(Boolean) || null;
}

export async function requestWalletProfilePermission(
  options: WalletProfileOptions
): Promise<WalletProfilePermission> {
  const fields = normalizeFields(options.fields);
  const provider = options.provider || (await requireProvider());
  const result = await provider.request({
    method: 'wallet_requestPermissions',
    params: [{ yeying_profile: { fields } }],
  });
  if (!Array.isArray(result)) {
    throw new Error('Wallet returned an invalid profile permission response');
  }
  const permission = result.map(parsePermission).find(Boolean);
  if (!permission) throw new Error('Wallet did not grant profile permission');
  const granted = new Set(getGrantedProfileFields(permission));
  if (fields.some(field => !granted.has(field))) {
    throw new Error('Wallet did not grant all requested profile fields');
  }
  return permission;
}

export async function getWalletProfile(options: WalletProfileOptions): Promise<WalletProfileResult> {
  const fields = normalizeFields(options.fields);
  const provider = options.provider || (await requireProvider());
  const result = await provider.request({
    method: 'yeying_getProfile',
    params: [{ fields }],
  });
  if (!result || typeof result !== 'object') {
    throw new Error('Wallet returned an invalid profile response');
  }
  const value = result as Record<string, unknown>;
  const profileSource = value.profile;
  if (typeof value.address !== 'string' || !profileSource || typeof profileSource !== 'object') {
    throw new Error('Wallet returned an invalid profile response');
  }
  const profile: WalletProfile = {};
  for (const field of fields) {
    const fieldValue = (profileSource as Record<string, unknown>)[field];
    if (typeof fieldValue === 'string') profile[field] = fieldValue;
  }
  return {
    address: value.address,
    chainId: typeof value.chainId === 'string' ? value.chainId : null,
    profile,
  };
}

export async function revokeWalletProfilePermission(provider?: Eip1193Provider): Promise<void> {
  const target = provider || (await requireProvider());
  await target.request({
    method: 'wallet_revokePermissions',
    params: [{ yeying_profile: {} }],
  });
}

export async function connectAndGetWalletProfile(
  options: ConnectWalletProfileOptions
): Promise<WalletProfileResult> {
  const fields = normalizeFields(options.fields);
  const provider = options.provider || (await requireProvider());
  const accounts = await provider.request({ method: 'eth_requestAccounts' });
  if (!Array.isArray(accounts) || typeof accounts[0] !== 'string') {
    throw new Error('Wallet did not return an account');
  }
  if (options.requestPermission !== false) {
    const permission = await getWalletProfilePermission(provider);
    const granted = new Set(getGrantedProfileFields(permission));
    const missing = fields.filter(field => !granted.has(field));
    if (missing.length > 0) {
      await requestWalletProfilePermission({ provider, fields: missing });
    }
  }
  return getWalletProfile({ provider, fields });
}
