# SDK能力

本文档合并原有：
- `SDK能力与账户管理设计.md`
- `能力矩阵.md`
- `库的定位与能力边界.md`

目标：用一个文档同时回答“这是什么、怎么选路线、怎么落地接入”。

## 1. 定位与边界

`@yeying-community/web3-bs` 的定位是：

> 浏览器端 DApp 连接、会话、认证、授权与存储接入 SDK

更具体地说：
- 以 EIP-1193 钱包为优先入口
- 统一封装 Provider 发现、连接会话、SIWE 登录、UCAN 授权、中心化认证与 WebDAV 存储接入
- 面向 DApp 前端集成，不承担后端鉴权逻辑

它是什么：
- 浏览器端前端集成 SDK
- DApp 访问编排层（钱包 / App 钱包 / 中心化服务 / WebDAV）
- 会话管理层（连接会话、认证会话、授权会话）

它不是什么：
- 不是链上交易构造与合约调用 SDK
- 不是后端 UCAN/JWT 校验库
- 不是 Node.js 服务端 SDK
- 不是 WalletConnect / deep link / app bridge 本身

实现边界：
- 钱包协议语义由钱包仓库定义
- audience / capability / app scope 由服务端定义
- `web3-bs` 负责前端如何调用这些能力

## 2. 路线与能力矩阵

路线定义：
- 钱包插件：浏览器内已安装插件钱包
- App 钱包：钱包 App 或桥接层向前端暴露 Provider
- 中心化服务：不依赖链上钱包，直接接中心化认证/授权

| 能力 | 钱包插件 | App 钱包 | 中心化服务 | 说明 |
| --- | --- | --- | --- | --- |
| Provider 发现 | ✅ | ⚠️ | ❌ | `getProvider` 适合插件；App 钱包通常需要外部先注入/适配 |
| 请求账户 | ✅ | ✅ | ❌ | 依赖 EIP-1193 `eth_requestAccounts` |
| 标准消息签名 | ✅ | ✅ | ❌ | `signMessage` |
| challenge / SIWE 登录 | ✅ | ✅ | ❌ | `loginWithChallenge` |
| access token 缓存 / refresh | ✅ | ✅ | ✅ | `setAccessToken` / `authFetch` / `refreshAccessToken` |
| UCAN Session 创建 | ✅ | ⚠️ | ❌ | 优先 `yeying_ucan_session`；不可用时使用本地 session |
| UCAN Root / Invocation | ✅ | ⚠️ | ❌ | Root 走 SIWE；Invocation 走 UCAN 签名 |
| 多后端 UCAN 授权 | ✅ | ⚠️ | ❌ | 通过 delegation/invocation 按 audience/capability 下发 |
| 中心化 session token | ✅ | ✅ | ✅ | `createCentralSession` |
| 中心化 UCAN 签发 | ✅ | ✅ | ✅ | `issueCentralUcan` |
| WebDAV 直接访问（JWT/UCAN） | ✅ | ✅ | ✅ | `createWebDavClient` |
| WebDAV + UCAN 自动初始化 | ✅ | ⚠️ | ❌ | `initWebDavStorage` |
| DApp 会话编排 | ✅ | ⚠️ | ❌ | `initDappSession` |

说明：
- `✅`：天然支持
- `⚠️`：可支持，但需要额外前提（尤其是 provider 适配或钱包能力）
- `❌`：该路线下不成立或不是典型用法

选型建议：
- 已有浏览器插件：优先钱包插件路线
- 移动端 Web 且可接 App 钱包：走 App 钱包路线
- 更关注接入效率或无钱包条件：走中心化服务路线
- 需要多后端统一授权：优先 UCAN 路线

## 3. 账户与会话管理设计

### 3.1 账户使用策略

- 页面初始化先读取 `eth_accounts`，避免无意义弹窗
- 用户主动点击连接时再调用 `eth_requestAccounts`
- 优先复用“上次选择账户”，不存在时回退 `accounts[0]`

示例：

```ts
import { getProvider, getPreferredAccount } from '@yeying-community/web3-bs';

const provider = await getProvider({ timeoutMs: 3000 });
const { account } = await getPreferredAccount({
  provider,
  autoConnect: false,
});
```

### 3.2 账户变更处理

账户变化后建议清理认证与授权缓存，重新发起登录授权流程：

```ts
import { watchAccounts, clearAccessToken, clearUcanSession } from '@yeying-community/web3-bs';

const unsubscribe = watchAccounts(provider, () => {
  clearAccessToken({ storeToken: false });
  clearUcanSession();
});
```

### 3.3 三层会话模型

- 连接会话：钱包连接状态与当前账户
- 认证会话：SIWE/JWT 或中心化 token
- 授权会话：UCAN Session、Root、Delegation、Invocation

## 4. 登录与授权模型

### 4.1 SIWE + JWT（单后端优先）

典型流程：
1. `POST /api/v1/public/auth/challenge`
2. 钱包签名 challenge
3. `POST /api/v1/public/auth/verify`
4. 使用 access token 调用业务接口
5. access 过期后 `POST /api/v1/public/auth/refresh`
6. 退出时 `POST /api/v1/public/auth/logout`

推荐 API 组合：
- `loginWithChallenge`
- `authFetch`
- `refreshAccessToken`
- `logout`

### 4.2 UCAN（多后端授权）

典型流程：
1. `createUcanSession`
2. `getOrCreateUcanRoot`（SIWE bridge）
3. 可选 `createDelegationUcan`
4. `createInvocationUcan`（按 audience + capability）
5. `authUcanFetch` 访问目标后端

说明：
- Root 建议作为跨后端“统一授权根”
- Invocation 作为短期令牌按后端和能力发放
- Root 或 Invocation 过期后按链路重建

### 4.3 SIWE 与 UCAN 对比

| 维度 | SIWE/JWT | UCAN |
| --- | --- | --- |
| Token 来源 | 后端签发 | 前端组装、后端校验 |
| 主要场景 | 单后端登录 | 多后端能力委任 |
| 续期方式 | refresh 接口 | 重建 invocation（必要时重建 root） |
| 权限表达 | 后端角色/策略 | `with/can` capability |

## 5. API 能力分组

### 5.1 Provider 与钱包接入

- `getProvider` / `requireProvider`
- `requestAccounts` / `getAccounts` / `watchAccounts`
- `getPreferredAccount`
- `getChainId` / `getBalance`
- `signMessage`

### 5.2 SIWE 与 JWT

- `loginWithChallenge`
- `authFetch`
- `refreshAccessToken`
- `logout`
- `getAccessToken` / `setAccessToken` / `clearAccessToken`

### 5.3 UCAN 授权

- `createUcanSession` / `getUcanSession`
- `createRootUcan` / `getOrCreateUcanRoot`
- `createDelegationUcan`
- `createInvocationUcan`
- `authUcanFetch`
- `normalizeUcanCapabilities`

### 5.4 中心化 UCAN

- `getCentralIssuerInfo`
- `createCentralSession`
- `issueCentralUcan`
- `createAndIssueCentralUcan`
- `authCentralUcanFetch`

### 5.5 WebDAV 与会话编排

- `createWebDavClient`
- `initWebDavStorage`
- `initDappSession`
- `deriveAppIdFromLocation` / `deriveAppIdFromHost`

## 6. 推荐接入组合

| 场景 | 推荐组合 |
| --- | --- |
| 插件钱包 + 单后端登录 | `getProvider` + `requestAccounts` + `loginWithChallenge` + `authFetch` |
| 插件钱包 + UCAN 多后端 | `createUcanSession` + `getOrCreateUcanRoot` + `createInvocationUcan` |
| App 钱包 + 登录 | `requestAccounts` + `signMessage` + `loginWithChallenge` + `authFetch` |
| 中心化 JWT | `setAccessToken` + `authFetch` + `createWebDavClient` |
| 中心化 UCAN | `createCentralSession` + `issueCentralUcan` + `authCentralUcanFetch` |
| WebDAV 直接访问 | `createWebDavClient` |
| WebDAV + UCAN 自动初始化 | `initWebDavStorage` |

## 7. 工程与安全注意事项

- 仅支持浏览器环境（依赖 `window` / `fetch` / `localStorage` / `IndexedDB`）
- `baseUrl` 只填服务根地址，子路径放 `prefix`
- capability 资源格式必须与目标服务定义一致（建议统一 `with/can`）
- 多钱包支持不代表高级能力跨钱包完全等价，取决于钱包能力实现
- 建议统一 `appId` 生成规则，避免 `localhost` 与 `127.0.0.1` 产生两套目录

## 8. 相关阅读

- [快速上手](./快速上手.md)
- [移动端认证与授权选型指南](./移动端认证与授权选型指南.md)
- [开放接口规范](./开放接口规范.yaml)
