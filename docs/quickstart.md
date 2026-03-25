# 快速上手

本文档按“前端 DApp 最常见的 4 个接入目标”来组织，而不是按源码文件组织。

## 1. 安装

```bash
npm install @yeying-community/web3-bs
```

## 2. 场景一：只做钱包接入与签名

适用场景：
- 只需要发现钱包、连接账户、签一段消息

```ts
import { getProvider, requestAccounts, signMessage } from '@yeying-community/web3-bs';

const provider = await getProvider({ preferYeYing: true });
if (!provider) throw new Error('No injected wallet provider');

const accounts = await requestAccounts({ provider });
const address = accounts[0];
if (!address) throw new Error('No account available');

const signature = await signMessage({
  provider,
  address,
  message: 'hello web3-bs',
});
```

说明：
- `getProvider` 会优先走 EIP-6963 发现，再回退到 `window.ethereum`
- `signMessage` 使用标准 EIP-1193 方法，不依赖 UCAN

## 3. 场景二：DApp 用 challenge 快速登录后端

适用场景：
- 后端提供 `/challenge` + `/verify` + `/refresh`
- 前端想要统一管理 access token

```ts
import {
  loginWithChallenge,
  authFetch,
  refreshAccessToken,
} from '@yeying-community/web3-bs';

const login = await loginWithChallenge({
  baseUrl: 'https://api.example.com/api/v1/public/auth',
});

const profileRes = await authFetch(
  'https://api.example.com/api/v1/public/profile',
  { method: 'GET' },
  { baseUrl: 'https://api.example.com/api/v1/public/auth' }
);

const refreshed = await refreshAccessToken({
  baseUrl: 'https://api.example.com/api/v1/public/auth',
});
```

说明：
- `loginWithChallenge` 负责 challenge -> sign -> verify
- `authFetch` 会自动带 `Bearer <token>`
- 请求返回 401 时，`authFetch` 会尝试刷新一次

## 4. 场景三：用 UCAN 一次授权访问多个后端

适用场景：
- 需要“登录一次 / 授权一次”，访问多个后端
- 钱包侧支持 YeYing UCAN RPC

```ts
import {
  createUcanSession,
  getOrCreateUcanRoot,
  createInvocationUcan,
  authUcanFetch,
} from '@yeying-community/web3-bs';

const provider = await window.YeYingWeb3.getProvider({ preferYeYing: true });
const session = await createUcanSession({ provider });

const root = await getOrCreateUcanRoot({
  provider,
  session,
  capabilities: [{ resource: 'profile', action: 'read' }],
});

const ucan = await createInvocationUcan({
  issuer: session,
  audience: 'did:web:api.example.com',
  capabilities: [{ resource: 'profile', action: 'read' }],
  proofs: [root],
});

const res = await authUcanFetch(
  'https://api.example.com/api/v1/public/profile',
  { method: 'GET' },
  { ucan }
);
```

说明：
- 这条链路依赖钱包提供 `yeying_ucan_session` / `yeying_ucan_sign`
- `root` 是 SIWE bridge 证明
- 每个后端需要使用自己的 `audience`

## 5. 场景四：接入 WebDAV 存储

适用场景：
- DApp 需要文件上传、下载、目录、回收站、配额
- 后端已有 WebDAV 服务

### 5.1 直接用 token 创建 WebDAV Client

```ts
import { createWebDavClient } from '@yeying-community/web3-bs';

const appId = window.location.host || '127.0.0.1:8001';

const client = createWebDavClient({
  baseUrl: 'https://webdav.example.com',
  prefix: '/dav',
  token: '<JWT_OR_UCAN>',
});

await client.upload(`/apps/${appId}/hello.txt`, 'Hello WebDAV');
const text = await client.downloadText(`/apps/${appId}/hello.txt`);
```

### 5.2 用 UCAN 自动初始化 WebDAV

```ts
import { initWebDavStorage } from '@yeying-community/web3-bs';

const appId = window.location.host || '127.0.0.1:8001';

const storage = await initWebDavStorage({
  baseUrl: 'https://webdav.example.com',
  prefix: '/dav',
  audience: 'did:web:webdav.example.com',
  appId,
  capabilities: [{ resource: `app:${appId}`, action: 'write' }],
});

await storage.client.upload(`${storage.appDir}/hello.txt`, 'Hello WebDAV');
```

说明：
- `baseUrl` 只填根地址，不带路径
- 子路径统一通过 `prefix` 指定
- WebDAV app scope 默认对应 `/apps/<appId>`
- `appId` 建议使用当前域名或 `IP:端口`

## 6. 场景五：移动端无插件，走中心化 UCAN

适用场景：
- 手机浏览器没有钱包插件
- 允许引入中心化会话和中心化 UCAN 签发服务

```ts
import {
  createCentralSession,
  issueCentralUcan,
  authCentralUcanFetch,
} from '@yeying-community/web3-bs';

const session = await createCentralSession({
  baseUrl: 'https://api.example.com/api/v1/public/auth/central',
  subject: 'mobile-user-001',
});

const issued = await issueCentralUcan({
  baseUrl: 'https://api.example.com/api/v1/public/auth/central',
  sessionToken: session.sessionToken,
  audience: 'did:web:api.example.com',
  capabilities: [{ resource: 'profile', action: 'read' }],
});

const res = await authCentralUcanFetch(
  'https://api.example.com/api/v1/public/profile/me',
  { method: 'GET' },
  {
    ucan: issued.ucan,
    baseUrl: 'https://api.example.com/api/v1/public/auth/central',
  }
);
```

说明：
- 这是“中心化 UCAN”路径
- 它解决的是“移动端无插件如何拿到可被后端接受的授权 token”
- 它不等价于钱包本地创建 UCAN

## 7. 最常见的接入选择

- 只做钱包连接：用 `getProvider` + `requestAccounts` + `signMessage`
- 只做后端登录：用 `loginWithChallenge` + `authFetch`
- 多后端授权：用 `createUcanSession` + `createInvocationUcan`
- 文件存储：用 `createWebDavClient` 或 `initWebDavStorage`
- 移动端无插件：优先看 [移动端认证方案总览](/root/code/web3-bs/docs/mobile-auth-options.md)

## 8. 进一步阅读

- [定位与能力边界](/root/code/web3-bs/docs/positioning.md)
- [完整设计说明](/root/code/web3-bs/docs/sdk-design.md)
- [移动端认证方案总览](/root/code/web3-bs/docs/mobile-auth-options.md)
