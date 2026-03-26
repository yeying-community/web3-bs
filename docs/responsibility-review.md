# 基于 Wallet 协议文档的职责复评

本文基于以下文档重新评审 `web3-bs` 的职责边界：

- [/root/code/wallet/docs/dapp-connection-flow.md](/root/code/wallet/docs/dapp-connection-flow.md)
- [/root/code/wallet/docs/siwe-protocol.md](/root/code/wallet/docs/siwe-protocol.md)
- [/root/code/wallet/docs/ucan-protocol.md](/root/code/wallet/docs/ucan-protocol.md)
- [/root/code/wallet/docs/backup-sync-webdav.md](/root/code/wallet/docs/backup-sync-webdav.md)

## 1. 复评结论

`web3-bs` 的定位仍然合理，但职责需要更精确地收敛为：

> **DApp 浏览器端连接与接入 SDK**

更完整地说：

> **负责把 DApp 的钱包连接、会话维护、登录、授权、存储访问需求，翻译为钱包调用和后端请求的浏览器端编排层**

这和“钱包插件中间库”有明显区别。它不是钱包协议的定义者，也不是服务端鉴权规则的定义者。

## 2. 从 Wallet 文档看到的真实责任分层

Wallet 文档已经把 3 层边界讲得很清楚：

### 2.1 钱包负责什么

钱包负责用户交互与签名能力本身：

- 站点连接授权与站点是否已授权的判断
- 锁定 / 解锁流程
- SIWE 消息识别、结构化展示、风险提示
- ReCap / UCAN 能力摘要展示
- UCAN Session Key 创建与签名
- 对外暴露 RPC：
  - `eth_requestAccounts`
  - `personal_sign`
  - `yeying_ucan_session`
  - `yeying_ucan_sign`

这意味着：

- **UCAN session 是钱包能力，不是 SDK 能力**
- **SIWE 风险提示与审批体验是钱包职责，不是 SDK 职责**

## 2.2 后端负责什么

后端负责认证结果与授权策略的最终裁决：

- challenge 生成与 verify
- token 签发与 refresh
- UCAN 验签
- audience / capability / constraint 校验
- WebDAV 资源路径与 app scope 策略
- 资源命名规则、动作语义、租户隔离策略

这意味着：

- **协议里的资源命名不是 `web3-bs` 说了算**
- **`web3-bs` 不应把某个 capability 格式包装成唯一标准**

## 2.3 `web3-bs` 应该负责什么

`web3-bs` 的职责应当是 DApp 侧接入编排：

- 发现并选择钱包 Provider
- 兼容 YeYing、MetaMask 等 EIP-1193 钱包
- 兼容能通过适配层暴露 EIP-1193 的 App 钱包
- 封装常见前端登录流程（challenge -> sign -> verify）
- 管理浏览器端 token / session 缓存
- 管理连接会话、账户偏好、central session、UCAN cache
- 组装 UCAN Root / Invocation 请求载荷
- 为 DApp 提供统一的请求助手（`authFetch` / `authUcanFetch`）
- 提供 WebDAV 客户端与 DApp 存储初始化封装
- 在无插件场景下，提供中心化会话 / 中心化 UCAN 的补充路径

## 3. 这次复评后，对 `web3-bs` 的职责判断

## 3.1 合理的部分

以下能力放在 `web3-bs` 中是合理的：

- Provider 发现与首选钱包策略
- 多接入对象兼容：浏览器插件钱包、App 钱包适配层、中心化服务
- 前端 challenge 登录封装
- token 缓存与自动刷新
- 连接会话与访问会话维护
- UCAN Root / Invocation 组装
- WebDAV 客户端
- `initDappSession` 这类 DApp 侧会话编排能力

这些都是典型的“前端接入层”职责。

## 3.2 需要收敛的部分

以下内容如果继续扩大，会让职责变模糊：

- 把 UCAN 资源命名规范定义在 SDK 中
- 把某个后端服务的授权模型写成 SDK 默认标准
- 把中心化 UCAN 描述成与钱包 UCAN 等价
- 让 SDK 文档替代钱包协议文档或服务端协议文档

这里最关键的是：

> `web3-bs` 可以帮助 DApp 传递 capability，但不应该成为 capability 语义的唯一来源。

## 4. 最重要的发现：资源命名不应由 SDK 统一拍板

Wallet 文档中的 Router / Chat / WebDAV 模板，推荐资源格式是：

- `app:<scope>:<appId>`

而当前 `web3-bs` 及 WebDAV 侧文档里，更多使用：

- `app:<appId>`

Wallet 文档也明确说了：

- `app:<appId>` 是历史兼容格式
- `app:all:<appId>` 是推荐模板之一

因此结论很明确：

- `web3-bs` 不应宣称某一种 capability 资源格式是“统一标准”
- `web3-bs` 文档应该写成：
  - **capability 的资源/动作由目标服务策略决定**
  - SDK 只负责传递和组装，不负责制定协议标准

这也是本次复评里最值得收紧的一点。

## 5. 中心化 UCAN 应该怎么看

从 wallet 协议分层看：

- 钱包侧 UCAN：用户控制密钥，钱包签名
- 中心化 UCAN：服务端发行，前端领取并转发

所以中心化 UCAN 放在 `web3-bs` 中并非不合理，但必须明确：

- 它是**移动端无插件 / 中心化接入补充方案**
- 它不是钱包 UCAN 的等价替代
- 它不应该成为 README 中的主路径叙述

更合适的做法是：

- 钱包 UCAN 是主路径
- 中心化 UCAN 是 fallback / mobile-specific 路径

## 6. WebDAV 在 `web3-bs` 中是否合理

合理。

原因不是“WebDAV 是钱包能力”，而是：

- DApp 确实需要一个前端可直接使用的存储客户端
- WebDAV 与认证 token 紧密相关
- `baseUrl` / `prefix` / `Authorization` / `appDir` 都属于前端接入层关注点

但文档要写清楚：

- `web3-bs` 提供的是 **WebDAV client**
- 不是 WebDAV 服务标准定义
- 不是 WebDAV 授权策略定义者

## 7. 推荐职责定义

基于 wallet/docs，建议把 `web3-bs` 的职责统一写成下面这段：

> `web3-bs` 是一个浏览器端 DApp 接入 SDK，负责在前端统一封装钱包 Provider 发现、多钱包/多接入方式兼容、连接会话维护、SIWE 风格登录、UCAN 请求组装、中心化移动端补充认证路径，以及 WebDAV 客户端访问能力。  
> 它不定义钱包审批规则，不定义服务端授权策略，也不定义最终的 capability 语义；这些分别由钱包与后端服务负责。

## 8. 推荐的文档结构结论

为了避免职责混乱，建议三类文档各说各的：

- 钱包仓库文档：协议解释、审批流程、风险提示、钱包 RPC 语义
- `web3-bs` 文档：DApp 如何调用 SDK，如何拼接前后端流程
- 后端服务文档：audience / capability / app scope / token verify 策略

## 9. 最终判断

最终判断是：

- **定位合理**
- **职责需要收敛表达**
- **最需要修正的是“协议标准由 SDK 统一定义”的暗示**

更准确的职责不是：

> 钱包插件中间库

而是：

> **面向 DApp 的浏览器端连接、会话、认证、授权与存储接入编排 SDK**
