import {
  Eip1193Provider,
  Eip6963ProviderDetail,
  ProviderDiscoveryOptions,
  ProviderInfo,
  RequestAccountsOptions,
  AccountSelection,
  PreferredAccountOptions,
  WatchAccountsOptions,
  AccountsChangedHandler,
  WatchProviderOptions,
  ProviderChangedHandler,
  WalletErrorInfo,
  FocusPendingApprovalResult,
} from './types';

const YEYING_RDNS = 'io.github.yeying';
const DEFAULT_TIMEOUT = 1000;
const DEFAULT_ACCOUNT_STORAGE_KEY = 'yeying:last_account';
const DEFAULT_PROVIDER_POLL_INTERVAL = 100;
const DEFAULT_PROVIDER_MAX_POLLS = 20;
const requestAccountsInFlight = new WeakMap<Eip1193Provider, Promise<string[]>>();

function isProvider(value: unknown): value is Eip1193Provider {
  return !!value && typeof (value as Eip1193Provider).request === 'function';
}

function getWindowEthereum(): Eip1193Provider | null {
  if (typeof window === 'undefined') return null;
  const ethereum = (window as unknown as { ethereum?: unknown }).ethereum;
  return isProvider(ethereum) ? ethereum : null;
}

function getWindowProviderCandidates(): Eip1193Provider[] {
  if (typeof window === 'undefined') return [];

  const source = window as unknown as Record<string, unknown>;
  const candidates: Eip1193Provider[] = [];
  const addProvider = (provider: unknown) => {
    if (isProvider(provider) && !candidates.includes(provider)) {
      candidates.push(provider);
    }
  };

  for (const name of [
    'ethereum',
    'yeeying',
    'yeying',
    'coinbaseWallet',
    'bitkeep',
    'tokenpocket',
    '__YEYING_PROVIDER__',
  ]) {
    addProvider(source[name]);
  }

  const ethereum = getWindowEthereum();
  if (Array.isArray(ethereum?.providers)) {
    for (const provider of ethereum.providers) {
      addProvider(provider);
    }
  }

  return candidates;
}

function readStoredAccount(storageKey: string): string | null {
  if (typeof localStorage === 'undefined') return null;
  try {
    return localStorage.getItem(storageKey);
  } catch {
    return null;
  }
}

function writeStoredAccount(storageKey: string, account: string | null): void {
  if (typeof localStorage === 'undefined') return;
  try {
    if (account) {
      localStorage.setItem(storageKey, account);
    } else {
      localStorage.removeItem(storageKey);
    }
  } catch {
    // ignore storage errors
  }
}

function selectPreferredAccount(
  accounts: string[],
  stored: string | null,
  preferStored: boolean
): string | null {
  if (preferStored && stored && accounts.includes(stored)) {
    return stored;
  }
  return accounts[0] || null;
}

export function isYeYingProvider(provider?: Eip1193Provider | null, info?: ProviderInfo): boolean {
  if (!provider) return false;
  if (provider.isYeYing) return true;
  const name = (info?.name || '').toLowerCase();
  const rdns = (info?.rdns || '').toLowerCase();
  return rdns === YEYING_RDNS || name.includes('yeying');
}

function selectBestProvider(
  candidates: Eip6963ProviderDetail[],
  preferYeYing: boolean
): Eip1193Provider | null {
  if (candidates.length === 0) return selectBestWindowProvider(preferYeYing);
  if (preferYeYing) {
    const yeying = candidates.find(c => isYeYingProvider(c.provider, c.info));
    if (yeying) return yeying.provider;
  }
  return candidates[0].provider;
}

function selectBestWindowProvider(preferYeYing: boolean): Eip1193Provider | null {
  const candidates = getWindowProviderCandidates();
  if (candidates.length === 0) return null;
  if (preferYeYing) {
    const yeying = candidates.find(provider => isYeYingProvider(provider));
    if (yeying) return yeying;
  }
  return candidates[0];
}

export async function getProvider(
  options: ProviderDiscoveryOptions = {}
): Promise<Eip1193Provider | null> {
  const preferYeYing = options.preferYeYing !== false;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
  const windowProvider = selectBestWindowProvider(preferYeYing);

  if (preferYeYing && isYeYingProvider(windowProvider)) {
    return windowProvider;
  }

  if (typeof window === 'undefined') {
    return windowProvider;
  }

  const discovered: Eip6963ProviderDetail[] = [];
  let resolved = false;

  return await new Promise(resolve => {
    const cleanup = () => {
      window.removeEventListener('eip6963:announceProvider', onAnnounce as EventListener);
      window.removeEventListener('ethereum#initialized', onEthereumInitialized as EventListener);
      if (timeoutId) clearTimeout(timeoutId);
    };

    const safeResolve = (provider: Eip1193Provider | null) => {
      if (resolved) return;
      resolved = true;
      cleanup();
      resolve(provider);
    };

    const onAnnounce = (event: Event) => {
      const detail = (event as CustomEvent<Eip6963ProviderDetail>).detail;
      if (!detail?.provider) return;
      discovered.push(detail);

      if (preferYeYing && isYeYingProvider(detail.provider, detail.info)) {
        safeResolve(detail.provider);
      }
    };

    const onEthereumInitialized = () => {
      const injected = selectBestWindowProvider(preferYeYing);
      if (preferYeYing && isYeYingProvider(injected)) {
        safeResolve(injected);
      }
    };

    window.addEventListener('eip6963:announceProvider', onAnnounce as EventListener);
    window.addEventListener('ethereum#initialized', onEthereumInitialized as EventListener, { once: true });

    const timeoutId = setTimeout(() => {
      if (resolved) return;
      const best =
        selectBestProvider(discovered, preferYeYing) ||
        windowProvider ||
        selectBestWindowProvider(preferYeYing);
      safeResolve(best || null);
    }, timeoutMs);

    try {
      window.dispatchEvent(new Event('eip6963:requestProvider'));
    } catch {
      // Ignore if browser doesn't support CustomEvent target
    }

    if (!preferYeYing && windowProvider) {
      safeResolve(windowProvider);
    }
  });
}

export function watchProvider(
  handler: ProviderChangedHandler,
  options: WatchProviderOptions = {}
): () => void {
  if (typeof window === 'undefined') {
    handler({ provider: null, present: false });
    return () => {};
  }

  const preferYeYing = options.preferYeYing !== false;
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_PROVIDER_POLL_INTERVAL;
  const maxPolls = options.maxPolls ?? DEFAULT_PROVIDER_MAX_POLLS;
  let stopped = false;
  let lastProvider: Eip1193Provider | null | undefined;
  let pollCount = 0;
  let pollTimer: ReturnType<typeof setTimeout> | null = null;

  const emit = () => {
    if (stopped) return;
    const provider = selectBestWindowProvider(preferYeYing);
    if (provider === lastProvider) return;
    lastProvider = provider;
    handler({ provider, present: !!provider });
  };

  const poll = () => {
    if (stopped) return;
    emit();
    pollCount += 1;
    if (lastProvider || pollCount >= maxPolls) return;
    pollTimer = setTimeout(poll, pollIntervalMs);
  };

  const handleProviderReady = () => {
    emit();
  };

  window.addEventListener('ethereum#initialized', handleProviderReady);
  window.addEventListener('eip6963:announceProvider', handleProviderReady as EventListener);

  try {
    window.dispatchEvent(new Event('eip6963:requestProvider'));
  } catch {
    // Ignore unsupported event dispatch environments.
  }

  poll();

  return () => {
    stopped = true;
    if (pollTimer) {
      clearTimeout(pollTimer);
    }
    window.removeEventListener('ethereum#initialized', handleProviderReady);
    window.removeEventListener('eip6963:announceProvider', handleProviderReady as EventListener);
  };
}

export function getWalletErrorMessage(error: unknown): string {
  if (!error) return '';
  if (typeof error === 'string') return error;
  if (error instanceof Error) return error.message || String(error);
  const message = (error as { message?: unknown }).message;
  if (typeof message === 'string') return message;
  return String(error);
}

export function getWalletErrorCode(error: unknown): number | null {
  const code = Number((error as { code?: unknown })?.code);
  if (!Number.isNaN(code)) return code;
  const causeCode = Number((error as { cause?: { code?: unknown } })?.cause?.code);
  if (!Number.isNaN(causeCode)) return causeCode;
  return null;
}

export function classifyWalletError(error: unknown): WalletErrorInfo {
  const code = getWalletErrorCode(error);
  const message = getWalletErrorMessage(error);
  const lowerMessage = message.toLowerCase();

  if (code === 4001 || lowerMessage.includes('user rejected')) {
    return { type: 'userRejected', code, message };
  }

  if (
    code === 4900 ||
    lowerMessage.includes('disconnected') ||
    lowerMessage.includes('reconnect') ||
    lowerMessage.includes('not connected')
  ) {
    return { type: 'disconnected', code, message };
  }

  if (lowerMessage.includes('timeout')) {
    return { type: 'timeout', code, message };
  }

  if (
    lowerMessage.includes('no injected wallet provider') ||
    lowerMessage.includes('未检测到钱包')
  ) {
    return { type: 'notFound', code, message };
  }

  return { type: 'unknown', code, message };
}

export function isUserRejectedWalletAction(error: unknown): boolean {
  return classifyWalletError(error).type === 'userRejected';
}

export function isWalletReconnectError(error: unknown): boolean {
  const type = classifyWalletError(error).type;
  return type === 'disconnected' || type === 'timeout';
}

export async function requireProvider(
  options: ProviderDiscoveryOptions = {}
): Promise<Eip1193Provider> {
  const provider = await getProvider(options);
  if (!provider) {
    throw new Error('No injected wallet provider found');
  }
  return provider;
}

export async function requestAccounts(
  options: RequestAccountsOptions = {}
): Promise<string[]> {
  const provider = options.provider || (await requireProvider());
  const dedupe = options.dedupe !== false;
  if (dedupe) {
    const pending = requestAccountsInFlight.get(provider);
    if (pending) return pending;
  }

  const request = provider.request({
    method: 'eth_requestAccounts',
  }).then(accounts => (Array.isArray(accounts) ? accounts : []));

  if (!dedupe) return request;

  requestAccountsInFlight.set(provider, request);
  try {
    return await request;
  } finally {
    requestAccountsInFlight.delete(provider);
  }
}

export async function focusPendingApproval(
  provider?: Eip1193Provider
): Promise<FocusPendingApprovalResult> {
  const p = provider || (await requireProvider());
  const result = await p.request({
    method: 'wallet_focusPendingApproval',
  });

  if (!result || typeof result !== 'object') {
    return { focused: false, type: null };
  }

  const payload = result as Record<string, unknown>;
  return {
    focused: Boolean(payload.focused),
    type: typeof payload.type === 'string' ? payload.type : null,
    requestId:
      typeof payload.requestId === 'string' ? payload.requestId : null,
    origin: typeof payload.origin === 'string' ? payload.origin : '',
    tabId:
      typeof payload.tabId === 'number' && Number.isFinite(payload.tabId)
        ? payload.tabId
        : null,
  };
}

export async function getAccounts(provider?: Eip1193Provider): Promise<string[]> {
  const p = provider || (await requireProvider());
  const accounts = (await p.request({ method: 'eth_accounts' })) as string[];
  return Array.isArray(accounts) ? accounts : [];
}

export async function getChainId(provider?: Eip1193Provider): Promise<string | null> {
  const p = provider || (await requireProvider());
  const chainId = (await p.request({ method: 'eth_chainId' })) as string;
  return typeof chainId === 'string' ? chainId : null;
}

export async function getPreferredAccount(
  options: PreferredAccountOptions = {}
): Promise<AccountSelection> {
  const provider = options.provider || (await requireProvider());
  const storageKey = options.storageKey || DEFAULT_ACCOUNT_STORAGE_KEY;
  const preferStored = options.preferStored !== false;
  let accounts = await getAccounts(provider);
  if (accounts.length === 0 && options.autoConnect) {
    accounts = await requestAccounts({ provider });
  }
  const stored = readStoredAccount(storageKey);
  const account = selectPreferredAccount(accounts, stored, preferStored);
  writeStoredAccount(storageKey, account);
  return { account, accounts };
}

export function watchAccounts(
  provider: Eip1193Provider,
  handler: AccountsChangedHandler,
  options: WatchAccountsOptions = {}
): () => void {
  const storageKey = options.storageKey || DEFAULT_ACCOUNT_STORAGE_KEY;
  const preferStored = options.preferStored !== false;
  return onAccountsChanged(provider, (accounts) => {
    const stored = readStoredAccount(storageKey);
    const account = selectPreferredAccount(accounts, stored, preferStored);
    writeStoredAccount(storageKey, account);
    handler({ account, accounts });
  });
}

export async function getBalance(
  provider?: Eip1193Provider,
  address?: string,
  blockTag: string = 'latest'
): Promise<string> {
  const p = provider || (await requireProvider());
  let target = address;
  if (!target) {
    const accounts = await getAccounts(p);
    target = accounts[0];
  }
  if (!target) {
    throw new Error('No account available for balance');
  }

  const balance = (await p.request({
    method: 'eth_getBalance',
    params: [target, blockTag],
  })) as string;
  if (typeof balance !== 'string') {
    throw new Error('Invalid balance response');
  }
  return balance;
}

export function onAccountsChanged(
  provider: Eip1193Provider,
  handler: (accounts: string[]) => void
): () => void {
  provider.on?.('accountsChanged', handler);
  return () => provider.removeListener?.('accountsChanged', handler);
}

export function onChainChanged(
  provider: Eip1193Provider,
  handler: (chainId: string) => void
): () => void {
  provider.on?.('chainChanged', handler);
  return () => provider.removeListener?.('chainChanged', handler);
}
