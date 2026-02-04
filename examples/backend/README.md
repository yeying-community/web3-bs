# 后端示例（多语言）启动说明

本目录下包含 Node / Go / Python / Java 四个版本的后端示例，接口行为一致：
- `/api/v1/public/auth/challenge`
- `/api/v1/public/auth/verify`
- `/api/v1/public/auth/refresh`
- `/api/v1/public/auth/logout`
- `/api/v1/public/profile`

`/api/v1/public/profile` 同时支持：
- JWT access token（原有流程）
- UCAN token（`Authorization: Bearer <UCAN>`）

## Node 版本

路径：`examples/backend/node/server.js`

启动：
```bash
node examples/backend/node/server.js
```

脚本启动：
```bash
./scripts/backend.sh start node
./scripts/backend.sh start node --setup
```

多后端同时启动（默认端口）：
```bash
./scripts/backend.sh start all
./scripts/backend.sh start all --setup
```

## Go 版本

路径：`examples/backend/go/main.go`

启动：
```bash
cd examples/backend/go

go run .
```

脚本启动：
```bash
./scripts/backend.sh start go
./scripts/backend.sh start go --setup
```

## Python 版本

路径：`examples/backend/python/app.py`

安装依赖并启动：
```bash
cd examples/backend/python

pip install -r requirements.txt
python app.py
```

脚本启动：
```bash
./scripts/backend.sh start python
./scripts/backend.sh start python --setup
```

## Java 版本

路径：`examples/backend/java/src/main/java/com/yeying/demo/AuthServer.java`

构建并启动：
```bash
cd examples/backend/java

mvn -q -DskipTests package
mvn -q exec:java -Dexec.mainClass="com.yeying.demo.AuthServer"
```

脚本启动：
```bash
./scripts/backend.sh start java
./scripts/backend.sh start java --setup
```

支持 start/stop/restart/status 和 all。
提示：脚本可加 `--setup` 先安装依赖并构建 `dist`，再启动服务。
提示：使用 `start/restart` 启动单一目标时，脚本会先停止其它语言版本，避免端口冲突。
提示：多后端联调时可加 `--no-stop` 保留其它服务运行。
提示：后端日志统一输出到 `.tmp/backend-logs`。

## 通用环境变量

所有语言版本均支持以下环境变量（未设置则使用默认值）：

- `PORT`：服务端口（默认：Go `3201` / Java `3202` / Node `3203` / Python `3204`）
- `JWT_SECRET`：JWT 签名密钥（默认 `replace-this-in-production`）
- `ACCESS_TTL_MS`：Access Token 过期时间（毫秒，默认 `900000`）
- `REFRESH_TTL_MS`：Refresh Token 过期时间（毫秒，默认 `604800000`）
- `COOKIE_SAMESITE`：`lax` / `strict` / `none`（默认 `lax`）
- `COOKIE_SECURE`：`true/false`（默认 `false`，仅 HTTPS 时使用 `true`）
- `CORS_ORIGINS`：允许跨域的 Origin 列表（逗号分隔）
  - 默认包含：当前服务端口 + `:8000`/`:8001` + 多后端端口 `3201-3204`

UCAN 相关环境变量（可选）：
- `UCAN_AUD`：服务 DID（默认 `did:web:127.0.0.1:<PORT>`）
- `UCAN_RESOURCE`：资源（默认 `profile`）
- `UCAN_ACTION`：动作（默认 `read`）
  - WebDAV 场景建议：`UCAN_RESOURCE=app:<appId>`，`UCAN_ACTION=read,write`，其中 `appId` 使用前端域名或 IP:端口。

多后端联调注意：
- 访问不同端口的后端时，请将前端 Origin 加入 `CORS_ORIGINS`
- 对应 UCAN 调用需匹配 `UCAN_AUD`（例如 `did:web:127.0.0.1:3202`）

部分语言版本还支持：
- `BASE_DIR`：静态资源根目录（可选）
  - Go / Python / Java 版本会用它定位 `examples/frontend` 与 `dist`

## 跨域访问提示

如果前端不是同域（例如 `http://127.0.0.1:8001`）：
1. 设置 `CORS_ORIGINS` 包含该 Origin
2. 使用 `credentials: 'include'`
3. 如果是跨站 Cookie，请设置：
   - `COOKIE_SAMESITE=none`
   - `COOKIE_SECURE=true`（必须 HTTPS）
