export type WebDavAuth =
  | { type: 'bearer'; token: string }
  | { type: 'basic'; username: string; password: string };

export type WebDavClientOptions = {
  baseUrl: string;
  prefix?: string;
  auth?: WebDavAuth;
  token?: string;
  fetcher?: typeof fetch;
  credentials?: RequestCredentials;
};

export type WebDavRequestOptions = {
  headers?: Record<string, string>;
  auth?: WebDavAuth;
  token?: string;
  depth?: number | 'infinity';
  overwrite?: boolean;
  contentType?: string;
  signal?: AbortSignal;
};

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '');
}

function normalizePrefix(prefix?: string): string {
  if (!prefix || prefix === '/') return '';
  let next = prefix.startsWith('/') ? prefix : `/${prefix}`;
  next = next.replace(/\/+$/, '');
  return next;
}

function normalizePath(path: string): string {
  if (!path || path === '/') return '/';
  const next = path.startsWith('/') ? path : `/${path}`;
  return encodeURI(next);
}

function joinUrl(baseUrl: string, path: string): string {
  const base = normalizeBaseUrl(baseUrl);
  const suffix = path.startsWith('/') ? path : `/${path}`;
  return `${base}${suffix}`;
}

function resolveAuthHeader(auth?: WebDavAuth, token?: string): string | null {
  if (auth?.type === 'bearer') {
    return `Bearer ${auth.token}`;
  }
  if (auth?.type === 'basic') {
    const raw = `${auth.username}:${auth.password}`;
    return `Basic ${btoa(raw)}`;
  }
  if (token) {
    return `Bearer ${token}`;
  }
  return null;
}

export class WebDavClient {
  private baseUrl: string;
  private prefix: string;
  private auth?: WebDavAuth;
  private token?: string;
  private fetcher: typeof fetch;
  private credentials?: RequestCredentials;

  constructor(options: WebDavClientOptions) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.prefix = normalizePrefix(options.prefix);
    this.auth = options.auth;
    this.token = options.token;
    this.fetcher = options.fetcher || ((input, init) => fetch(input, init));
    this.credentials = options.credentials;
  }

  setToken(token: string | null) {
    this.token = token || undefined;
  }

  setAuth(auth?: WebDavAuth) {
    this.auth = auth;
  }

  private buildUrl(path: string): string {
    const webdavPath = `${this.prefix}${normalizePath(path)}`;
    return `${this.baseUrl}${webdavPath}`;
  }

  private buildHeaders(options?: WebDavRequestOptions): Headers {
    const headers = new Headers(options?.headers || {});
    const authHeader = resolveAuthHeader(options?.auth || this.auth, options?.token || this.token);
    if (authHeader) {
      headers.set('Authorization', authHeader);
    }
    if (options?.depth !== undefined) {
      headers.set('Depth', String(options.depth));
    }
    if (typeof options?.overwrite === 'boolean') {
      headers.set('Overwrite', options.overwrite ? 'T' : 'F');
    }
    if (options?.contentType) {
      headers.set('Content-Type', options.contentType);
    }
    return headers;
  }

  async request(
    method: string,
    path: string,
    body?: BodyInit | null,
    options: WebDavRequestOptions = {}
  ): Promise<Response> {
    const response = await this.fetcher(this.buildUrl(path), {
      method,
      headers: this.buildHeaders(options),
      body: body ?? undefined,
      credentials: this.credentials,
      signal: options.signal,
    } as RequestInit);

    if (!response.ok) {
      throw new Error(`WebDAV ${method} ${path} failed: ${response.status} ${response.statusText}`);
    }

    return response;
  }

  async listDirectory(path: string = '/', depth: number | 'infinity' = 1): Promise<string> {
    const res = await this.request('PROPFIND', path, null, { depth });
    return await res.text();
  }

  async download(path: string): Promise<Response> {
    return await this.request('GET', path);
  }

  async downloadText(path: string): Promise<string> {
    const res = await this.download(path);
    return await res.text();
  }

  async downloadArrayBuffer(path: string): Promise<ArrayBuffer> {
    const res = await this.download(path);
    return await res.arrayBuffer();
  }

  async upload(path: string, content: BodyInit, contentType?: string): Promise<Response> {
    return await this.request('PUT', path, content, { contentType });
  }

  async createDirectory(path: string): Promise<Response> {
    return await this.request('MKCOL', path);
  }

  async ensureDirectory(path: string): Promise<void> {
    if (!path || path === '/') return;
    const segments = path.split('/').filter(Boolean);
    if (segments.length === 0) return;

    let current = '';
    for (const segment of segments) {
      current = `${current}/${segment}`;
      const res = await this.fetcher(this.buildUrl(current), {
        method: 'MKCOL',
        headers: this.buildHeaders(),
        credentials: this.credentials,
      } as RequestInit);

      if (res.ok) continue;
      if (res.status === 405) continue;
      throw new Error(`WebDAV MKCOL ${current} failed: ${res.status} ${res.statusText}`);
    }
  }

  async remove(path: string): Promise<Response> {
    return await this.request('DELETE', path);
  }

  async move(path: string, destination: string, overwrite: boolean = true): Promise<Response> {
    const destinationUrl = destination.startsWith('http')
      ? destination
      : this.buildUrl(destination);
    return await this.request('MOVE', path, null, {
      headers: { Destination: destinationUrl },
      overwrite,
    });
  }

  async copy(path: string, destination: string, overwrite: boolean = true): Promise<Response> {
    const destinationUrl = destination.startsWith('http')
      ? destination
      : this.buildUrl(destination);
    return await this.request('COPY', path, null, {
      headers: { Destination: destinationUrl },
      overwrite,
    });
  }

  async getQuota(): Promise<unknown> {
    const res = await this.fetcher(joinUrl(this.baseUrl, '/api/v1/public/webdav/quota'), {
      method: 'GET',
      headers: this.buildHeaders(),
      credentials: this.credentials,
    });
    if (!res.ok) {
      throw new Error(`WebDAV quota failed: ${res.status} ${res.statusText}`);
    }
    return await res.json();
  }

  async listRecycle(): Promise<unknown> {
    const res = await this.fetcher(joinUrl(this.baseUrl, '/api/v1/public/webdav/recycle/list'), {
      method: 'GET',
      headers: this.buildHeaders(),
      credentials: this.credentials,
    });
    if (!res.ok) {
      throw new Error(`WebDAV recycle list failed: ${res.status} ${res.statusText}`);
    }
    return await res.json();
  }

  async recoverRecycle(hash: string): Promise<unknown> {
    const res = await this.fetcher(joinUrl(this.baseUrl, '/api/v1/public/webdav/recycle/recover'), {
      method: 'POST',
      headers: this.buildHeaders({ contentType: 'application/json' }),
      body: JSON.stringify({ hash }),
      credentials: this.credentials,
    });
    if (!res.ok) {
      throw new Error(`WebDAV recycle recover failed: ${res.status} ${res.statusText}`);
    }
    return await res.json();
  }

  async deleteRecycle(hash: string): Promise<unknown> {
    const res = await this.fetcher(joinUrl(this.baseUrl, '/api/v1/public/webdav/recycle/permanent'), {
      method: 'DELETE',
      headers: this.buildHeaders({ contentType: 'application/json' }),
      body: JSON.stringify({ hash }),
      credentials: this.credentials,
    });
    if (!res.ok) {
      throw new Error(`WebDAV recycle delete failed: ${res.status} ${res.statusText}`);
    }
    return await res.json();
  }

  async clearRecycle(): Promise<unknown> {
    const res = await this.fetcher(joinUrl(this.baseUrl, '/api/v1/public/webdav/recycle/clear'), {
      method: 'DELETE',
      headers: this.buildHeaders(),
      credentials: this.credentials,
    });
    if (!res.ok) {
      throw new Error(`WebDAV recycle clear failed: ${res.status} ${res.statusText}`);
    }
    return await res.json();
  }
}

export function createWebDavClient(options: WebDavClientOptions): WebDavClient {
  return new WebDavClient(options);
}
