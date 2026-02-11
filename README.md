# YeYing Inject Wallet SDK

轻量级注入钱包 SDK，专注浏览器端 EIP-1193 Provider。默认优先选择 YeYing Wallet（支持 EIP-6963 多钱包发现）。
仅支持浏览器环境（依赖 `window` / `localStorage` / `fetch`）。

功能要点：
- 浏览器端 EIP-1193 Provider 辅助库
- 默认优先 YeYing Wallet
- 内置 `signMessage` / `loginWithChallenge` / `refresh` / `logout` 等方法
- 支持 UCAN Session + SIWE Bridge，用于多后端授权

## 安装

```bash
npm install @yeying-community/web3-bs
```

更多集成与流程说明见 `docs/sdk-design.md`。

## 示例

- Frontend Dapp (HTML): `examples/frontend/dapp.html`
- Frontend Dapp (TS module): `examples/frontend/main.ts`
- Backend server (Node): `examples/backend/node/server.js`
- Backend server (Go): `examples/backend/go/main.go`
- Backend server (Python): `examples/backend/python/app.py`
- Backend server (Java): `examples/backend/java/src/main/java/com/yeying/demo/AuthServer.java`

## 本地验证

1. 构建 SDK：`npm run build`
2. 启动后端：`scripts/backend.sh start node`（将 `node` 替换为 `go` / `python` / `java`）
3. 启动前端：`python3 -m http.server 8001 --bind 127.0.0.1`
4. 访问：`http://127.0.0.1:8001/examples/frontend/dapp.html`
5. 确保安装 YeYing 钱包扩展插件
6. 点击：`Detect Provider` → `Connect Wallet` → `Login`

提示：如果前端来自其他域名，请设置
`COOKIE_SAMESITE=none` 且 `COOKIE_SECURE=true` 并使用 HTTPS，
以便 `refresh_token` Cookie 能随 `credentials: 'include'` 发送。

## 后端脚本用法

通用格式：
`./scripts/backend.sh <start|stop|restart|status> <node|go|python|java|all> [--setup] [--no-stop]`

示例：
```bash
# 启动 Node 后端
./scripts/backend.sh start node

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

## 常见问题

### 刷新token失败

清理旧 Cookie 后重新登录：在浏览器 DevTools → Application → Cookies → http://127.0.0.1:8001 删除 refresh_token，再点 Login 后再点 Refresh Token。

### WebDAV 提示 invalid token

报错示例：`authentication failed` / `invalid token`（通常来自 WebDAV 服务端鉴权中间件）。

排查与解决：
- 确认 `baseUrl` 指向 WebDAV 服务（默认 `http://127.0.0.1:6065`），不要误用 320x 认证后端。
- `baseUrl` 不应包含任何路径；若服务挂载在子路径，请用 `prefix` 指定（例如 `/dav`）。
- `audience` 必须与 WebDAV 服务端 `web3.ucan.audience` 一致（例如 `did:web:127.0.0.1:6065`）。
- `capabilities` 与服务端要求一致（`web3.ucan.required_resource` / `required_action`，或环境变量 `WEBDAV_UCAN_RESOURCE` / `WEBDAV_UCAN_ACTION`）。
  - WebDAV 推荐使用 `app:<appId>#read|write`，不要用 `app:*`；`appId` 建议使用前端域名或 IP:端口。
  - 若启用了 app scope（推荐 `required_resource=app:*`），请确保路径在 `/apps/<appId>/`（或 `app_scope.path_prefix`）下。
- Token 过期或缓存异常时，清理 UCAN 会话并重新登录/生成 Root + Invocation。

### UCAN audience mismatch

日志示例：
```
[2026-01-31T05:19:44.478Z] UCAN profile failed { error: 'UCAN audience mismatch' }
```

解决思路：
- 生成 UCAN 时的 `audience` 必须与目标后端的 `UCAN_AUD` 完全一致。
  - 例如 Node 后端：`did:web:127.0.0.1:3203`
  - 例如 WebDAV 服务：`did:web:127.0.0.1:6065`
- 多后端联调时，确保每个后端使用对应的 `audience` 生成 Invocation UCAN。
