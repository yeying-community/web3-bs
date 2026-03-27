# 方案 A：WalletConnect / Deep Link 到钱包 App（移动端保留 UCAN）

## 1. 适用场景

- 用户愿意安装第三方钱包 App
- 需要保留链上身份与 UCAN 形态
- 希望移动端体验接近 PC 插件

## 2. 核心思路

移动端 Web 通过 WalletConnect 连接钱包 App，获得 EIP-1193 Provider 能力，再走 SIWE/UCAN。

关键限制：
- 当前 UCAN 会话依赖 **YeYing 专有 RPC**（`yeying_ucan_session` / `yeying_ucan_sign`）。
- 绝大多数钱包只提供通用 `personal_sign`，不支持 UCAN Session API。

因此此方案有两种实现路径：
- **A1：钱包 App 支持 YeYing UCAN RPC**（最理想）
- **A2：仅支持 SIWE/JWT（无法创建 UCAN Session）** → 退化为 JWT 登录

## 3. 详细落地流程（A1：支持 YeYing UCAN RPC）

1) 集成 WalletConnect（或钱包自带 deep link SDK）
2) 获取 Provider（EIP-1193）
3) 走 UCAN 流程：
   - `createUcanSession()` → 生成 UCAN Session Key
   - `getOrCreateUcanRoot()` → SIWE Root Proof
   - `createInvocationUcan()` → Invocation Token
4) 访问多个后端：`Authorization: Bearer <UCAN>`
5) WebDAV：使用 `initWebDavStorage`（UCAN 模式）

示例（UCAN 模式）：
```ts
import { initWebDavStorage } from '@yeying-community/web3-bs';

const appId = window.location.host || '127.0.0.1:8001';
const storage = await initWebDavStorage({
  baseUrl: 'https://webdav.example.com',
  prefix: '/dav',
  audience: 'did:web:webdav.example.com',
  appId,
  capabilities: [{ with: `app:all:${appId}`, can: 'write' }],
});
```

## 4. 详细落地流程（A2：仅支持 SIWE/JWT）

1) WalletConnect 建立连接
2) 仅使用 `personal_sign` 完成 SIWE
3) 后端签发 JWT
4) 前端使用 JWT 访问后端 + WebDAV（使用 `createWebDavClient`）

## 5. 后端改造清单

- 若支持 UCAN：保持现有 UCAN 验证逻辑
- 若仅 JWT：各后端统一验证 JWT（或通过网关）

## 6. 风险与注意

- WalletConnect 依赖外部钱包体验
- UCAN 专有 RPC 可能无法获得支持

## 7. 结论

- 若钱包支持 YeYing UCAN RPC，此方案最接近 PC 体验。
- 若不支持，则只能退化为 SIWE/JWT。
