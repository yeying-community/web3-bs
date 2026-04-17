# YeYing Browser DApp Access SDK

浏览器端 DApp 接入 SDK，用于统一封装钱包连接、会话维护、SIWE 登录、UCAN 多后端授权、中心化服务接入和 WebDAV 存储访问。
它优先面向 EIP-1193 / EIP-6963 钱包生态，可对接 YeYing、MetaMask 等浏览器钱包；也可对接能暴露 EIP-1193 能力的 App 钱包或中心化认证服务。仅支持浏览器环境（依赖 `window` / `localStorage` / `fetch`）。

功能要点：
- 浏览器端 EIP-1193 Provider 辅助库
- 默认优先 YeYing Wallet，也兼容其他 EIP-1193 钱包
- 内置 `signMessage` / `loginWithChallenge` / `refresh` / `logout` 等方法
- 支持 UCAN Session + SIWE Bridge，用于多后端授权
- 支持中心化 UCAN Demo API：`createCentralSession` / `issueCentralUcan` / `authCentralUcanFetch`
- 统一封装前端连接会话、token 会话与 WebDAV 访问会话，降低 DApp 集成成本

## 安装

```bash
npm install @yeying-community/web3-bs
```

更多集成与流程说明见 `docs/sdk-design.md`。
推荐先读：
- `docs/README.md`
- `docs/positioning.md`
- `docs/quickstart.md`
- `docs/capability-matrix.md`

## 接入路线

- 钱包插件路线：适合浏览器内已有 YeYing、MetaMask 等插件钱包的 DApp；优先使用 `getProvider`、`loginWithChallenge`，并可扩展到 UCAN 多后端授权（钱包 UCAN RPC 优先，不支持时 SDK 自动回退本地 Ed25519 session）
- App 钱包路线：适合移动端 Web；前提是钱包 App 或桥接层能暴露 EIP-1193 provider，通常使用 `requestAccounts`、`signMessage`、`loginWithChallenge`
- 中心化服务路线：适合无钱包、无插件或更关注接入成本的场景；使用 JWT 或中心化 UCAN，通常组合 `setAccessToken`、`authFetch`、`createCentralSession`、`issueCentralUcan`

能力对比见 `docs/capability-matrix.md`，详细接入步骤见 `docs/quickstart.md`。

## 示例

- Frontend Dapp (HTML): `examples/frontend/dapp.html`
- Frontend Dapp Central UCAN Tab: `examples/frontend/dapp.html`（`UCAN 授权（服务）`）
- Frontend Dapp (TS module): `examples/frontend/main.ts`
- Backend server (Node.js): `examples/backend/node/server.js`
- Backend server (Go): `examples/backend/go/main.go`
- Backend server (Python): `examples/backend/python/app.py`
- Backend server (Java): `examples/backend/java/src/main/java/com/yeying/demo/AuthServer.java`

## 本地验证

1. 构建 SDK：`npm run build`
2. 启动后端：`scripts/backend.sh start nodejs`（将 `nodejs` 替换为 `go` / `python` / `java`）
3. 启动前端：`python3 -m http.server 8001 --bind 127.0.0.1`
4. 访问：`http://127.0.0.1:8001/examples/frontend/dapp.html`
5. 确保安装 YeYing 钱包扩展插件
6. 点击：`Detect Provider` → `Connect Wallet` → `Login`

提示：如果前端来自其他域名，请设置
`COOKIE_SAMESITE=none` 且 `COOKIE_SECURE=true` 并使用 HTTPS，
以便 `refresh_token` Cookie 能随 `credentials: 'include'` 发送。

## 后端脚本用法

通用格式：
`./scripts/backend.sh <start|stop|restart|status> <nodejs|go|python|java|all> [--setup] [--no-stop]`

示例：
```bash
# 启动 Node.js 后端
./scripts/backend.sh start nodejs

# 启动 Go 后端并安装依赖/构建
./scripts/backend.sh start go --setup

# 查看全部后端状态
./scripts/backend.sh status all

# 重启 Python 后端
./scripts/backend.sh restart python

# 停止所有后端
./scripts/backend.sh stop all

# 同时启动多个后端（不停止已运行的服务）
./scripts/backend.sh start all --no-stop
```

说明：
- 日志位于 `.tmp/backend-logs`
- 进程 PID 位于 `.tmp/backend-pids`
- 可通过环境变量传递端口/秘钥/TTL 等配置（如 `PORT`、`JWT_SECRET` 等）

## 多后端联调（不同端口）

可同时启动多语言后端（不同端口），验证 UCAN 多后端授权：

```bash
./scripts/backend.sh start all
./scripts/backend.sh start all --setup
```

默认端口：
- Go `3201`
- Java `3202`
- Node `3203`
- Python `3204`

前端调用不同端口的后端时：
- 将前端 Origin 加入 `CORS_ORIGINS`（例如 `http://127.0.0.1:3203`）
- UCAN 调用的 `audience` 与后端 `UCAN_AUD` 一致（如 `did:web:127.0.0.1:3202`）

提示：`examples/frontend/dapp.html` 已内置多后端列表，可在一次 UCAN 授权后依次调用多个服务。
提示：Demo 的 UCAN 流程按协议链路实现为 `Root（SIWE） -> Delegation -> Invocation`，便于按步骤理解多后端授权。

## 常见问题

### 如何快速验证能力矩阵（钱包 UCAN + 本地回退）

执行：

```bash
npm run check:capabilities
```

该脚本会自动验证：
- 钱包 UCAN RPC 路径（`createUcanSession` 返回 `source=wallet`）
- UCAN 本地回退路径（钱包不支持 `yeying_ucan_*` 时 `source=local`）
- `createRootUcan` + `createInvocationUcan` 两条链路
- `initWebDavStorage` 的 UCAN 自动初始化
- 中心化 UCAN API 是否已导出（`createCentralSession` / `issueCentralUcan` / `authCentralUcanFetch`）

### 刷新token失败

清理旧 Cookie 后重新登录：在浏览器 DevTools → Application → Cookies → http://127.0.0.1:8001 删除 refresh_token，再点 Login 后再点 Refresh Token。

### WebDAV 提示 invalid token

报错示例：`authentication failed` / `invalid token`（通常来自 WebDAV 服务端鉴权中间件）。

排查与解决：
- 确认 `baseUrl` 指向 WebDAV 服务（默认 `http://127.0.0.1:6065`），不要误用 320x 认证后端。
- `baseUrl` 不应包含任何路径；若服务挂载在子路径，请用 `prefix` 指定（例如 `/dav`）。
- `audience` 必须与 WebDAV 服务端 `web3.ucan.audience` 一致（例如 `did:web:127.0.0.1:6065`）。
- `capabilities` 与服务端要求一致（优先 `web3.ucan.required_capabilities`，兼容 `required_resource/required_action`）。
  - SDK 推荐使用 `with/can`（兼容 `resource/action`），例如：`{ with: "app:all:<appId>", can: "read,write" }`。
  - 推荐资源统一使用 `app:<scope>:<appId>`，常用为 `with=app:all:<appId>`；请确保路径在 `/apps/<appId>/`（或 `app_scope.path_prefix`）下。
- Token 过期或缓存异常时，清理 UCAN 会话并重新登录/生成 Root + Invocation。

### UCAN audience mismatch

日志示例：
```
[2026-01-31T05:19:44.478Z] UCAN profile failed { error: 'UCAN audience mismatch' }
```

解决思路：
- 生成 UCAN 时的 `audience` 必须与目标后端的 `UCAN_AUD` 完全一致。
  - 例如 Node.js 后端：`did:web:127.0.0.1:3203`
  - 例如 WebDAV 服务：`did:web:127.0.0.1:6065`
- 多后端联调时，确保每个后端使用对应的 `audience` 生成 Invocation UCAN。
