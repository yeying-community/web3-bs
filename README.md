# YeYing Inject Wallet SDK

轻量级注入钱包 SDK，专注浏览器端 EIP-1193 Provider。默认优先选择 YeYing Wallet（支持 EIP-6963 多钱包发现）。

## 安装

```bash
npm install @yeying-community/yeying-web3
```

## 钱包交互 API

### Provider 发现
- `getProvider(options?)`
  - 自动监听 `eip6963:announceProvider`
  - 默认优先 YeYing（`isYeYing` 或 `rdns: io.github.yeying`）

### 核心方法
- `requestAccounts({ provider? })`
- `getAccounts(provider?)`
- `getChainId(provider?)`
- `getBalance(provider?, address?, blockTag?)`
- `signMessage({ provider?, message, address?, method? })`
  - `method` 默认 `personal_sign`

### 事件
- `onAccountsChanged(provider, handler)`
- `onChainChanged(provider, handler)`

## 后端交互 API（推荐标准）

### 响应封装（严格）
所有响应必须使用以下封装结构：

```json
{
  "code": 0,
  "message": "ok",
  "data": { "...": "..." },
  "timestamp": 1730000000000
}
```

- `code = 0` 表示成功
- `code != 0` 表示失败；`data` 应为 `null`

### 1) 获取 Challenge

`POST /api/v1/public/auth/challenge`

请求
```json
{ "address": "0xabc123..." }
```

响应
```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "address": "0xabc123...",
    "challenge": "Sign to login...",
    "nonce": "random",
    "issuedAt": 1730000000000,
    "expiresAt": 1730000300000
  },
  "timestamp": 1730000000000
}
```

### 2) 验证签名

`POST /api/v1/public/auth/verify`

请求
```json
{ "address": "0xabc123...", "signature": "0x..." }
```

响应
```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "address": "0xabc123...",
    "token": "access-token",
    "expiresAt": 1730086400000,
    "refreshExpiresAt": 1730686400000
  },
  "timestamp": 1730000000000
}
```

说明
- `verify` 应设置 httpOnly 的 `refresh_token` Cookie（用于刷新 access token）。
- 访问受保护接口时，前端使用 `Authorization: Bearer <access-token>`。

### 3) 刷新 Access Token

`POST /api/v1/public/auth/refresh`

请求
- 依赖 httpOnly `refresh_token` Cookie

响应
```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "address": "0xabc123...",
    "token": "new-access-token",
    "expiresAt": 1730086400000,
    "refreshExpiresAt": 1730686400000
  },
  "timestamp": 1730000000000
}
```

### 4) 退出登录

`POST /api/v1/public/auth/logout`

响应
```json
{
  "code": 0,
  "message": "ok",
  "data": { "logout": true },
  "timestamp": 1730000000000
}
```

### SDK 绑定
- `loginWithChallenge` 会从 `data.challenge` 读取 challenge，从 `data.token` 读取 token。
- `refreshAccessToken` 调用 `/refresh` 并更新 access token（默认 `credentials: 'include'`）。
- `authFetch` 会自动携带 access token，遇到 401 会尝试刷新再重试一次。
- `logout` 会清理刷新 Cookie 并清空本地 access token（若设置 `storeToken`）。

## 示例

- Frontend Dapp (HTML): `examples/frontend/dapp.html`
- Frontend Dapp (TS module): `examples/frontend/main.ts`
- Backend server (Node): `examples/backend/node/server.js`
- Backend server (Go): `examples/backend/go/main.go`
- Backend server (Python): `examples/backend/python/app.py`
- Backend server (Java): `examples/backend/java/src/main/java/com/yeying/demo/AuthServer.java`

## 本地验证

1. 构建 SDK：`npm run build`
2. 启动后端：`node examples/backend/node/server.js`
3. 从后端服务器打开前端（同源 Cookie）：
   - `python3 -m http.server 8000 --directory examples/frontend`
   - `http://localhost:4001/dapp.html`
4. 确保安装 YeYing 钱包扩展并允许该站点访问
5. 点击：`Detect Provider` → `Connect Wallet` → `Login`

提示：如果前端来自其他域名，请设置
`COOKIE_SAMESITE=none` 且 `COOKIE_SECURE=true` 并使用 HTTPS，
以便 `refresh_token` Cookie 能随 `credentials: 'include'` 发送。
