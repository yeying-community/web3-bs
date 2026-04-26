# YeYing Browser DApp Access SDK

`web3-bs` 是浏览器端 DApp 接入 SDK，用于统一封装：

- 钱包连接（EIP-1193 / EIP-6963）
- SIWE challenge 登录与 JWT 鉴权请求
- UCAN 多后端授权（钱包 UCAN RPC 优先，失败可回退本地 Ed25519 session）
- 中心化 UCAN 发行服务接入
- WebDAV 文件访问与应用目录初始化

仅支持浏览器环境（依赖 `window` / `localStorage` / `fetch`）。

## 安装

```bash
npm install @yeying-community/web3-bs
```

## 能力概览

### 1) Provider 与账户

- `getProvider` / `requireProvider`
- `requestAccounts` / `getAccounts` / `getPreferredAccount` / `watchAccounts`
- `getChainId` / `getBalance`
- `onAccountsChanged` / `onChainChanged`

### 2) SIWE + JWT

- `signMessage`
- `loginWithChallenge`
- `authFetch`
- `refreshAccessToken`
- `logout`
- `getAccessToken` / `setAccessToken` / `clearAccessToken`

### 3) UCAN（钱包优先 + 本地回退）

- `createUcanSession` / `getUcanSession`
- `getOrCreateUcanRoot` / `createRootUcan`
- `createDelegationUcan` / `createInvocationUcan`
- `authUcanFetch`
- `normalizeUcanCapabilities`

说明：
- 能调用 `yeying_ucan_session` / `yeying_ucan_sign` 时，优先用钱包侧 UCAN session 签名。
- 不支持上述钱包 RPC 时，SDK 会回退到浏览器本地 Ed25519 session（IndexedDB 持久化）。

### 4) 中心化 UCAN

- `getCentralIssuerInfo`
- `createCentralSession`
- `issueCentralUcan`
- `createAndIssueCentralUcan`
- `authCentralUcanFetch`
- `getCentralSessionToken` / `setCentralSessionToken` / `clearCentralSessionToken`

### 5) WebDAV 与 DApp 会话编排

- `createWebDavClient`
- `initWebDavStorage`（自动生成/复用 WebDAV Invocation UCAN，可自动创建应用目录）
- `createShareLink` / `listShareLinks` / `revokeShareLink`（公开分享链接管理）
- `initDappSession`（SIWE 登录 + WebDAV UCAN 初始化）
- `deriveAppIdFromLocation` / `deriveAppIdFromHost`

## 常见接入方式

### 单后端登录（SIWE + JWT）

```ts
import { loginWithChallenge, authFetch } from '@yeying-community/web3-bs';

await loginWithChallenge({
  baseUrl: 'http://localhost:3203/api/v1/public/auth',
  storeToken: false,
});

const res = await authFetch(
  'http://localhost:3203/api/v1/public/profile',
  { method: 'GET' },
  { baseUrl: 'http://localhost:3203/api/v1/public/auth', storeToken: false }
);
```

### 多后端 UCAN + WebDAV

```ts
import { initWebDavStorage, deriveAppIdFromLocation } from '@yeying-community/web3-bs';

const appId = deriveAppIdFromLocation(window.location) || 'localhost-8001';
const webdav = await initWebDavStorage({
  baseUrl: 'http://localhost:6065',
  audience: 'did:web:localhost:6065',
  appId,
  capabilities: [{ with: `app:all:${appId}`, can: 'write' }],
});

await webdav.client.upload(`${webdav.appDir}/hello.txt`, 'Hello WebDAV');
```

### WebDAV 分享链接（warehouse）

```ts
import { createWebDavClient } from '@yeying-community/web3-bs';

const client = createWebDavClient({
  baseUrl: 'http://localhost:6065',
  token: '<JWT_OR_UCAN>',
});

// expiresValue = 0 表示长期（不过期）分享链接
const share = await client.createShareLink({
  path: '/apps/demo/hello.txt',
  expiresValue: 0,
  expiresUnit: 'day',
});

console.log(share.url);
```

分享链接权限边界（warehouse 当前实现）：
- 使用 UCAN 且 capability 带 `app` scope（如 `app:all:<appId>`）时，`createShareLink` / `listShareLinks` 仅允许授权目录内的文件路径。
- 使用 JWT（或未携带 UCAN `app` scope）时，不会自动套用上述目录过滤，最终范围由后端鉴权策略决定。

## Demo

- 前端 Demo（双 Tab：单后端 SIWE / 多后端 UCAN+WebDAV）：
  `examples/frontend/dapp.html`
- 前端 TS 示例：`examples/frontend/main.ts`
- 多语言后端示例：
  - Node: `examples/backend/node/server.js`
  - Go: `examples/backend/go/main.go`
  - Java: `examples/backend/java/src/main/java/com/yeying/demo/AuthServer.java`
  - Python: `examples/backend/python/app.py`

## 本地联调

1. 构建 SDK：`npm run build`
2. 启动后端（示例）：
   `./scripts/backend.sh start nodejs`
3. 启动前端：
   `python3 -m http.server 8001 --bind 127.0.0.1`
4. 打开：
   `http://127.0.0.1:8001/examples/frontend/dapp.html`

多后端联调：

```bash
./scripts/backend.sh start all
```

默认端口：
- Go `3201`
- Java `3202`
- Node `3203`
- Python `3204`

## CORS 注意事项

若你用 `http://[::]:8001` 打开页面，请确保后端 CORS 白名单包含该 Origin。  
建议统一加入：

```bash
CORS_ORIGINS=http://localhost:8001,http://127.0.0.1:8001,http://[::]:8001
```

## 本地软链接（开发）

将本仓库作为本地依赖链接到你的 DApp：

```bash
mkdir -p /path/to/your-dapp/node_modules/@yeying-community
ln -s /path/to/web3-bs /path/to/your-dapp/node_modules/@yeying-community/web3-bs
```

## 文档导航

- [文档导航](./docs/文档导航.md)
- [快速上手](./docs/快速上手.md)
- [SDK能力](./docs/SDK能力.md)
- [移动端认证与授权选型指南](./docs/移动端认证与授权选型指南.md)
- [接口规范（OpenAPI）](./docs/开放接口规范.yaml)
