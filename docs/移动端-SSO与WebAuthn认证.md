# SSO / WebAuthn 认证（JWT）

## 1. 适用场景

- 目标是移动端 Web 顺畅登录
- 不要求链上签名
- 可以接受中心化身份（SSO/JWT）

## 2. 核心思路

移动端使用 WebAuthn（Passkey）或 OIDC 登录，后端签发 JWT，所有后端统一验证 JWT。

## 3. 详细落地流程（WebAuthn）

### 注册（一次性）
1) `/auth/passkey/register/options`
2) `navigator.credentials.create()`
3) `/auth/passkey/register/verify`

### 登录
1) `/auth/passkey/login/options`
2) `navigator.credentials.get()`
3) `/auth/passkey/login/verify` → 返回 JWT

### 多后端访问
- 各后端验证 JWT
- 或 Auth 服务提供 Token Exchange

## 4. 前端使用本库（JWT 模式）

```ts
import {
  setAccessToken,
  authFetch,
  createWebDavClient,
  deriveAppIdFromLocation,
} from '@yeying-community/web3-bs';

setAccessToken(token, { storeToken: true });
const res = await authFetch('https://api.example.com/api/v1/public/profile');

const appId = deriveAppIdFromLocation(window.location) || 'localhost-8001';
const webdav = createWebDavClient({
  baseUrl: 'https://webdav.example.com',
  prefix: '/dav',
  token,
});
await webdav.upload(`/apps/${appId}/hello.txt`, 'Hello');
```

> 注意：`initWebDavStorage` 是 UCAN 模式；此方案用 JWT。

## 5. 后端改造清单

- 新增 WebAuthn 注册/登录接口
- JWT 统一验证（所有后端）
- 统一 `iss` / `aud` / `exp` 策略

## 6. 安全与注意

- 必须 HTTPS
- 验证 `origin` 与 `rpId`
- 防重放、挑战短期有效

## 7. 结论

移动端体验最佳、实现成本可控，但不再使用链上身份或 UCAN。
