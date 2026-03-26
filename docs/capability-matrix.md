# 能力矩阵

这张表回答一个核心问题：

> 不同接入路线下，`web3-bs` 到底能帮 DApp 做什么，哪些能力有前提条件？

## 1. 路线定义

- 钱包插件：浏览器内已安装插件钱包
- App 钱包：钱包 App 或桥接层向前端暴露 Provider
- 中心化服务：无钱包或不依赖链上身份，直接接中心化认证/授权服务

## 2. 核心能力矩阵

| 能力 | 钱包插件 | App 钱包 | 中心化服务 | 说明 |
| --- | --- | --- | --- | --- |
| Provider 发现 | ✅ | ⚠️ | ❌ | `getProvider` 适合插件；App 钱包通常需要外部先注入/适配 provider |
| 请求账户 | ✅ | ✅ | ❌ | 依赖 EIP-1193 `eth_requestAccounts` |
| 标准消息签名 | ✅ | ✅ | ❌ | `signMessage` 适用于 EIP-1193 provider |
| challenge / SIWE 登录 | ✅ | ✅ | ❌ | `loginWithChallenge` 需要签名能力 + 后端 challenge 接口 |
| access token 缓存 / refresh | ✅ | ✅ | ✅ | `setAccessToken` / `authFetch` / `refreshAccessToken` |
| UCAN Session 创建 | ⚠️ | ⚠️ | ❌ | 依赖 `yeying_ucan_session` |
| UCAN Root / Invocation | ⚠️ | ⚠️ | ❌ | 依赖 YeYing UCAN RPC；不是所有钱包都支持 |
| 多后端 UCAN 授权 | ⚠️ | ⚠️ | ❌ | 前提同上 |
| 中心化 session token | ❌ | ❌ | ✅ | `createCentralSession` |
| 中心化 UCAN 签发 | ❌ | ❌ | ✅ | `issueCentralUcan` |
| WebDAV 直接访问（JWT/UCAN） | ✅ | ✅ | ✅ | `createWebDavClient` |
| WebDAV + UCAN 自动初始化 | ⚠️ | ⚠️ | ❌ | `initWebDavStorage`，前提是钱包 UCAN 可用 |
| DApp 会话编排 | ✅ | ⚠️ | ❌ | `initDappSession` 当前偏插件 / 标准 provider 路线 |

说明：
- `✅`：该路线天然支持
- `⚠️`：可支持，但需要额外前提
- `❌`：该路线下不成立，或不是这条路线的典型用法

## 3. 最关键的前提条件

### 3.1 钱包插件路线

- 通用插件能力：连接、签名、challenge/SIWE 登录
- YeYing 增强能力：UCAN Session / UCAN Sign / 多后端 UCAN 授权

结论：
- 所有插件钱包不等价
- 标准 EIP-1193 能力比较通用
- UCAN 能力当前明显偏 YeYing 生态

### 3.2 App 钱包路线

- 前提不是“有 App”，而是“能拿到 provider”
- 如果 App 钱包只提供签名，不提供 UCAN RPC，则只能走 JWT / SIWE 路线

结论：
- `web3-bs` 可以接 App 钱包
- 但它不负责 WalletConnect / deep link / app bridge 本身

### 3.3 中心化服务路线

- 不依赖钱包
- 适合移动端无插件、无 App 钱包、或不强依赖链上身份的业务

结论：
- JWT 路线最简单
- 中心化 UCAN 是补充方案，不等价于钱包侧 UCAN

## 4. 推荐 API 组合

| 场景 | 推荐 API 组合 |
| --- | --- |
| 插件钱包 + 登录 | `getProvider` + `requestAccounts` + `loginWithChallenge` + `authFetch` |
| 插件钱包 + UCAN | `createUcanSession` + `getOrCreateUcanRoot` + `createInvocationUcan` |
| App 钱包 + 登录 | `requestAccounts` + `signMessage` + `loginWithChallenge` + `authFetch` |
| 中心化 JWT | `setAccessToken` + `authFetch` + `createWebDavClient` |
| 中心化 UCAN | `createCentralSession` + `issueCentralUcan` + `authCentralUcanFetch` |
| WebDAV 直接访问 | `createWebDavClient` |
| WebDAV + 钱包 UCAN | `initWebDavStorage` |

## 5. 选择建议

- 你已经有浏览器插件：先走钱包插件路线
- 你是移动端 Web，但能接钱包 App：走 App 钱包路线
- 你没有钱包能力或更关注接入成本：走中心化服务路线
- 你必须做多后端 UCAN：优先确认目标钱包是否支持 YeYing UCAN RPC
