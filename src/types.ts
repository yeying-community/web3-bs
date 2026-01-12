export type JsonRpcRequest = {
  method: string;
  params?: unknown[] | Record<string, unknown>;
};

export interface Eip1193Provider {
  request: (args: JsonRpcRequest) => Promise<unknown>;
  on?: {
    (event: 'accountsChanged', listener: (accounts: string[]) => void): void;
    (event: 'chainChanged', listener: (chainId: string) => void): void;
    (event: string, listener: (...args: unknown[]) => void): void;
  };
  removeListener?: {
    (event: 'accountsChanged', listener: (accounts: string[]) => void): void;
    (event: 'chainChanged', listener: (chainId: string) => void): void;
    (event: string, listener: (...args: unknown[]) => void): void;
  };
  isMetaMask?: boolean;
  isYeYing?: boolean;
}

export interface ProviderInfo {
  uuid?: string;
  name?: string;
  icon?: string;
  rdns?: string;
}

export interface Eip6963ProviderDetail {
  info: ProviderInfo;
  provider: Eip1193Provider;
}

export interface ProviderDiscoveryOptions {
  timeoutMs?: number;
  preferYeYing?: boolean;
}

export interface RequestAccountsOptions {
  provider?: Eip1193Provider;
}

export interface SignMessageOptions {
  provider?: Eip1193Provider;
  message: string;
  address?: string;
  method?: 'personal_sign' | 'eth_sign';
}

export interface AuthBaseOptions {
  baseUrl?: string;
  fetcher?: typeof fetch;
  credentials?: RequestCredentials;
  storeToken?: boolean;
  tokenStorageKey?: string;
}

export interface LoginWithChallengeOptions extends AuthBaseOptions {
  provider?: Eip1193Provider;
  address?: string;
  challengePath?: string;
  verifyPath?: string;
  signMethod?: 'personal_sign' | 'eth_sign';
}

export interface RefreshAccessTokenOptions extends AuthBaseOptions {
  refreshPath?: string;
}

export interface LogoutOptions extends AuthBaseOptions {
  logoutPath?: string;
}

export interface AuthFetchOptions extends AuthBaseOptions {
  refreshPath?: string;
  accessToken?: string | null;
  retryOnUnauthorized?: boolean;
}

export interface AuthTokenResult {
  token: string;
  response: unknown;
}
