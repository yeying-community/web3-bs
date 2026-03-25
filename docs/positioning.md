# 库的定位与能力边界

## 1. 结论

当前库的定位**总体合理**，但建议把表述从“注入钱包 SDK”升级为：

> **浏览器端 DApp 连接、会话、认证、授权与存储接入 SDK**

更具体一点：

> **以 EIP-1193 钱包为优先入口，统一封装 Provider 发现、连接会话维护、SIWE 登录、UCAN 授权、中心化认证/授权服务、WebDAV 存储接入的浏览器端 SDK**

这一定义比“钱包插件中间库”更准确，因为当前代码已经明显超出“钱包连接”本身，也不只服务于浏览器插件。

补充边界：

- 钱包协议语义由钱包仓库定义
- audience / capability / app scope 由后端服务定义
- `web3-bs` 负责 DApp 前端如何接这些能力

## 2. 为什么这个定位是合理的

从代码能力看，这个库已经形成了 4 层能力：

### 2.1 Provider 与连接层

- EIP-6963 Provider 发现
- EIP-1193 调用封装
- 默认优先 YeYing Wallet
- 账户选择与账户切换监听
- 兼容 MetaMask 等其他 EIP-1193 钱包
- 可接入能暴露 EIP-1193 能力的 App 钱包

对应实现：
- [provider.ts](/root/code/web3-bs/src/auth/provider.ts)

### 2.2 登录、认证与前端会话层

- 通用签名 `signMessage`
- 基于 challenge 的 SIWE 风格登录
- access token 本地缓存、刷新、注销
- `authFetch` 自动带 token、401 后自动刷新
- central session token 缓存
- UCAN session / root / invocation 的前端缓存与复用

对应实现：
- [siwe.ts](/root/code/web3-bs/src/auth/siwe.ts)

### 2.3 授权与多服务访问层

- 钱包侧 UCAN Session 创建
- SIWE Root Proof
- Delegation / Invocation UCAN
- 一次授权访问多个后端
- 中心化 UCAN Session / Issue / Fetch
- 面向多个后端服务的 audience/capability 请求组装

对应实现：
- [ucan.ts](/root/code/web3-bs/src/auth/ucan.ts)
- [central.ts](/root/code/web3-bs/src/auth/central.ts)

### 2.4 存储与资源访问层

- WebDAV 客户端
- WebDAV + UCAN 的应用目录封装
- DApp 一次初始化同时拿到登录态和存储态

对应实现：
- [webdav.ts](/root/code/web3-bs/src/storage/webdav.ts)
- [dapp.ts](/root/code/web3-bs/src/dapp.ts)

这说明它的实际角色不是“只帮你找钱包”，而是“帮 DApp 在浏览器里统一完成连接、会话、认证和资源访问接入”。

## 3. 它是什么

建议对外明确为以下定位：

- 一个**浏览器端** SDK
- 一个**前端集成层** SDK
- 一个以**钱包优先**为主，但也支持**App 钱包与中心化认证补充路径**的 SDK
- 一个面向 **DApp -> 钱包 / App 钱包 / 中心化服务 / WebDAV** 的访问编排 SDK
- 一个帮助 DApp **维护连接会话、认证会话、授权会话** 的 SDK

## 4. 它不是什么

如果不把这部分写清楚，后续使用者很容易预期错误。

- 不是通用区块链交互库
- 不是交易构造与链上写操作 SDK
- 不是智能合约调用框架
- 不是后端 UCAN/JWT 校验库
- 不是 Node.js 服务端 SDK
- 不是完整的钱包标准抽象层

尤其是 UCAN 这部分，当前实现并不是“对任意钱包通用”，而是**显式依赖 YeYing 钱包的专有 RPC 方法**：

- `yeying_ucan_session`
- `yeying_ucan_sign`

对应实现：
- [ucan.ts](/root/code/web3-bs/src/auth/ucan.ts)

这意味着：

- `signMessage` / `loginWithChallenge` 更接近通用 EIP-1193 / 中心化登录接入能力
- `createUcanSession` / `createInvocationUcan` 这条链路则明显是 **YeYing 优先能力**
- “支持 App 钱包”成立的前提是该钱包能提供 EIP-1193 或等价适配层

进一步说：

- SDK 可以帮助 DApp 组装 UCAN
- 但 UCAN session 的生成和签名仍然是钱包职责
- capability 的最终语义仍由目标服务决定

## 5. 当前定位最需要修正的地方

### 5.1 “Inject Wallet SDK” 过窄

当前 README 和 package 描述更像“钱包接入工具”，但代码已经包括：

- 连接会话维护
- token 管理
- 自动刷新
- 中心化 UCAN
- WebDAV 存储客户端
- DApp 会话编排

因此它已经是一个**DApp Access SDK**，而不只是 Inject Wallet SDK。

### 5.2 “统一集成方案”这个说法成立，但要加边界

“统一集成方案”这句话本身没问题，但必须加前提：

- 统一的是**浏览器端接入方式**
- 不是统一所有钱包能力
- 不是统一所有后端协议
- 在 UCAN 路径上，当前统一的是 **YeYing 生态 / 兼容实现**

## 6. 推荐对外描述

推荐 README / 官网 / npm 描述统一成类似下面这段：

> `@yeying-community/web3-bs` 是一个浏览器端 DApp 接入 SDK，用于统一封装钱包连接、前端会话维护、SIWE 登录、UCAN 多后端授权、中心化认证/授权服务与 WebDAV 存储接入能力。它优先面向 EIP-1193 钱包生态，同时兼容中心化服务接入场景，目标是显著降低 DApp 前端集成成本。它不负责链上交易构造，也不承担服务端鉴权逻辑。

## 7. 推荐的能力分组

为了让接入方快速理解，建议按下面 5 个入口介绍，而不是按文件介绍：

1. 钱包接入：Provider 发现、连接、账号监听、签名
2. 会话维护：账户选择、token 缓存、refresh、central session、UCAN cache
3. 后端登录：challenge 登录、token 管理、鉴权请求
4. 多后端授权：UCAN session / root / invocation
5. 存储接入：WebDAV client、应用目录与 prefix
6. 无插件移动端：中心化 UCAN / SSO / WebAuthn 方案

## 8. 对外文档应该强调的边界

- 仅支持浏览器环境
- `baseUrl` 只填写服务根地址，路径放到 `prefix`
- UCAN 路径默认要求支持 YeYing 专有 RPC
- 中心化 UCAN 是补充方案，不等价于钱包侧 UCAN
- WebDAV 是客户端封装，不是 WebDAV 服务本身
- capability 的资源格式不是 SDK 统一定义，必须以目标服务文档为准
- “支持多钱包”不等于所有高级能力都跨钱包等价，具体要看目标钱包是否提供所需能力

## 9. 建议结论

如果你们后续继续以现在的代码方向演进，这个库最合适的定位不是“钱包插件中间库”，而是：

> **DApp 浏览器端连接、会话、认证与访问 SDK**

其中“钱包”是第一入口，“App 钱包 / 中心化服务”是补充入口，“UCAN / JWT / WebDAV / 中心化移动端方案”是围绕 DApp 接后端服务的能力组合。
