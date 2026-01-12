# 后端示例（多语言）启动说明

本目录下包含 Node / Go / Python / Java 四个版本的后端示例，接口行为一致：
- `/api/v1/public/auth/challenge`
- `/api/v1/public/auth/verify`
- `/api/v1/public/auth/refresh`
- `/api/v1/public/auth/logout`
- `/api/v1/private/profile`

默认会静态服务前端页面与 SDK 构建产物：
- `http://localhost:4001/dapp.html`
- `http://localhost:4001/dist/yeying-web3.umd.js`

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

## 通用环境变量

所有语言版本均支持以下环境变量（未设置则使用默认值）：

- `PORT`：服务端口（默认 `4001`）
- `JWT_SECRET`：JWT 签名密钥（默认 `replace-this-in-production`）
- `ACCESS_TTL_MS`：Access Token 过期时间（毫秒，默认 `900000`）
- `REFRESH_TTL_MS`：Refresh Token 过期时间（毫秒，默认 `604800000`）
- `COOKIE_SAMESITE`：`lax` / `strict` / `none`（默认 `lax`）
- `COOKIE_SECURE`：`true/false`（默认 `false`，仅 HTTPS 时使用 `true`）
- `CORS_ORIGINS`：允许跨域的 Origin 列表（逗号分隔）
  - 默认包含：`http://localhost:4001`、`http://127.0.0.1:4001`、`http://localhost:8000`、`http://127.0.0.1:8000`、`http://localhost:8001`、`http://127.0.0.1:8001`

部分语言版本还支持：
- `BASE_DIR`：静态资源根目录（可选）
  - Go / Python / Java 版本会用它定位 `examples/frontend` 与 `dist`

## 跨域访问提示

如果前端不是同域（例如 `http://localhost:8001`）：
1. 设置 `CORS_ORIGINS` 包含该 Origin
2. 使用 `credentials: 'include'`
3. 如果是跨站 Cookie，请设置：
   - `COOKIE_SAMESITE=none`
   - `COOKIE_SECURE=true`（必须 HTTPS）
