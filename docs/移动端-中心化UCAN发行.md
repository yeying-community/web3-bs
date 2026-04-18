# 中心化 UCAN 发行（服务端签发）

## 1. 适用场景

- 希望保留“UCAN 形态”
- 可以接受中心化信任（非链上身份）

## 2. 核心思路

使用 SSO/WebAuthn 登录后，由 **Issuer 服务** 生成 UCAN（JWS EdDSA），后端改为信任该 Issuer。

## 3. 详细落地流程


## 3.1 序列图（中心化 UCAN 发行）

```mermaid
sequenceDiagram
  autonumber
  participant U as User (Mobile Web)
  participant FE as Frontend Web
  participant Auth as Auth/SSO Service
  participant Issuer as UCAN Issuer Service
  participant API as Backend Service

  U->>FE: 打开移动端 Web DApp
  FE->>Auth: 请求登录（SSO/WebAuthn）
  Auth->>U: 返回挑战 / 认证提示
  U->>Auth: 完成认证（Passkey/OIDC）
  Auth-->>FE: 返回登录会话/用户标识

  FE->>Issuer: 请求签发 UCAN (aud, cap, exp)
  Issuer-->>FE: 返回 UCAN (JWS, EdDSA)

  FE->>API: 调用业务接口 (Authorization: Bearer UCAN)
  API->>Issuer: 拉取/缓存 Issuer 公钥 (可选)
  API->>API: 校验 UCAN (aud/cap/exp + Issuer 可信)
  API-->>FE: 返回业务数据
```

1) 用户用 SSO/WebAuthn 登录
2) Issuer 服务签发 UCAN：
   - `iss` 为 Issuer DID
   - `aud` 指向后端服务
   - `cap` 由后端策略决定（推荐 `app:<scope>:<appId>`，常用 `app:all:<appId>`）
3) 前端携带 `Authorization: Bearer <UCAN>`
4) 后端验证：改为信任 Issuer 公钥（非钱包）

## 4. 后端改造清单

- UCAN 验签逻辑改为信任 Issuer DID（而非用户钱包）
- 不再要求 SIWE Root Proof
- 改变信任模型（需要安全审计）

## 5. 优缺点

- **优点**：仍可用 UCAN 形式在多后端分发
- **缺点**：不再是用户控制的 UCAN；安全语义改变

## 6. 结论

可行但会改变 UCAN 信任模型，需谨慎评估。

## 7. Demo 接口（当前实现）

Node 侧已提供最小可运行 Demo（需启用 `UCAN_CENTRAL_ISSUER_ENABLED=true`）：

- `GET /api/v1/public/auth/central/issuer`
  - 返回中心化 Issuer DID、默认 audience/capabilities
- `POST /api/v1/public/auth/central/session`
  - 入参：`{ "subject": "mobile-user-001" }`
  - 出参：`sessionToken`
- `POST /api/v1/public/auth/central/issue`
  - Header：`Authorization: Bearer <sessionToken>`
  - 入参：`{ "audience": "...", "capabilities": [{ "with": "app:all:mobile-demo", "can": "read" }] }`
  - 出参：`ucan`

使用 `ucan` 调用业务接口：

- `GET /api/v1/public/profile/me`
  - Header：`Authorization: Bearer <ucan>`

## 8. SDK 调用示例（web3-bs）

```ts
import {
  createCentralSession,
  issueCentralUcan,
  authCentralUcanFetch,
} from '@yeying-community/web3-bs';

const baseUrl = 'http://127.0.0.1:8100/api/v1/public/auth/central';
const profileUrl = 'http://127.0.0.1:8100/api/v1/public/profile/me';

const session = await createCentralSession({
  baseUrl,
  subject: 'mobile-user-001',
});

const issued = await issueCentralUcan({
  baseUrl,
  sessionToken: session.sessionToken,
  audience: 'did:web:localhost:8100',
  capabilities: [{ with: 'app:all:mobile-demo', can: 'read' }],
});

const res = await authCentralUcanFetch(
  profileUrl,
  { method: 'GET' },
  { ucan: issued.ucan }
);
console.log(await res.json());
```
