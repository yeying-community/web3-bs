# UCAN有效期与续期机制

本文档说明 `@yeying-community/web3-bs` 中 UCAN token 的有效期配置、过期判断和推荐续期策略。目标是让所有 DApp 使用同一套规则，而不是在各应用里各自硬编码。

## 1. 核心原则

`skew` 不是用来提前给用户报错的，而是用来判断“当前 Invocation Token 是否还值得复用”。

只要 Root / Session 还有效，SDK 就应该自动生成新的 Invocation Token，用户不应该感知 Invocation 过期。

用户真正需要重新操作的钱包授权，只应该发生在 Root / Session 过期、账户变化、能力不足或服务端拒绝继续授权时。

## 2. 为什么要自动刷新重试

只判断 token “当前还没过期”是不够的，但正确处理方式不是让业务自己预估请求耗时，而是让 SDK 统一处理过期后的刷新重试。

典型问题：
- 用户发起请求时，本地判断 token 仍有效。
- 服务端因为时钟差、校验策略或处理过程中 token 过期，最终返回 `UCAN expired`。
- 用户已经等待、上游可能已经消耗 token，但前端拿不到有效结果。

正确策略分两层：
- 请求前优化：用 `skew` 做很小的时钟安全提前量。如果 token 即将过期，就在请求发出前静默生成新的 Invocation Token。
- 请求后兜底：如果服务端仍返回 `UCAN expired`，SDK 自动重新生成 Invocation Token 并重试一次。

## 3. 有效期层次

### 3.1 Root UCAN

Root UCAN 是用户通过钱包签名建立的授权根。

默认有效期：
- `DEFAULT_UCAN_SESSION_TTL_MS`
- 当前值：24 小时

特点：
- 通常需要用户钱包签名。
- 过期后需要重新创建 Root。
- 如果钱包签名窗口被遮挡，应用应通过 SDK 的钱包弹窗聚焦能力唤回，而不是重复发起多个签名请求。

### 3.2 Local / Wallet UCAN Session

UCAN Session 是用于签发 Delegation / Invocation 的会话密钥。

默认有效期：
- `DEFAULT_UCAN_SESSION_TTL_MS`
- 当前值：24 小时

来源：
- 钱包支持 `yeying_ucan_session` 时，优先使用钱包托管 session。
- 钱包不支持时，SDK 回退到本地 Ed25519 session，并保存在 IndexedDB。

过期处理：
- session 过期后 SDK 会重新创建。
- 如果需要钱包参与，可能触发钱包交互。

### 3.3 Delegation UCAN

Delegation UCAN 用于把能力委托给另一个 audience。

默认有效期：
- `DEFAULT_UCAN_TOKEN_TTL_MS`
- 当前值：1 小时

特点：
- 适合短期委托。
- 过期后可在 Root 和 Session 仍有效时重新签发。

### 3.4 Invocation UCAN

Invocation UCAN 是真正发给目标服务的短期调用 token。

默认有效期：
- `DEFAULT_UCAN_TOKEN_TTL_MS`
- 当前值：1 小时

默认时钟偏移：
- `DEFAULT_UCAN_TOKEN_SKEW_MS`
- 当前值：1 分钟

特点：
- 应按 audience + capability 生成。
- 应短期有效，降低泄漏风险。
- 请求前如果进入 `skew` 窗口，SDK 应自动重新生成 Invocation Token。
- 正常情况下，Invocation Token 过期不应该打断用户正在发起的新请求。

### 3.5 中心化 UCAN / 中心化 Session

中心化 UCAN 由中心化服务签发。

特点：
- 有效期由中心化服务返回值决定。
- 前端仍应使用 SDK 的 token timing 工具判断是否足够支撑请求。
- 如果中心化 session 过期，需要走中心化 session 续期或重新登录。

## 4. SDK 默认值

| 常量 | 默认值 | 用途 |
| --- | --- | --- |
| `DEFAULT_UCAN_SESSION_TTL_MS` | 24 小时 | Root / Session 默认有效期 |
| `DEFAULT_UCAN_TOKEN_TTL_MS` | 1 小时 | Delegation / Invocation 默认有效期 |
| `DEFAULT_UCAN_TOKEN_SKEW_MS` | 1 分钟 | 判断 Invocation 是否需要换新的安全提前量 |

## 5. SDK 提供的通用能力

### 5.1 解析 token timing

```ts
import { getUcanTokenTiming } from '@yeying-community/web3-bs';

const timing = getUcanTokenTiming(ucan);

console.log(timing.valid);
console.log(timing.remainingMs);
console.log(timing.exp);
console.log(timing.nbf);
```

适用场景：
- UI 展示授权剩余时间。
- 请求前判断 token 是否仍可用。
- 调试 UCAN 过期问题。

### 5.2 判断 token 是否新鲜

```ts
import { isUcanTokenFresh } from '@yeying-community/web3-bs';

const ok = isUcanTokenFresh(ucan, {
  skewMs: 5_000,
});

if (!ok) {
  // 自动重新签发 invocation token 后再请求
}
```

通常不需要手动传 `skewMs`，使用 SDK 默认值即可。

### 5.3 自动获取可用 Invocation Token

业务应用优先使用 `getOrCreateInvocationUcan`，而不是自己判断后报错：

```ts
import { getOrCreateInvocationUcan } from '@yeying-community/web3-bs';

const ucan = await getOrCreateInvocationUcan({
  ucan: cachedInvocationToken,
  issuer: session,
  audience: 'did:web:router.example.com',
  capabilities: [{ with: 'app:all:chat', can: 'invoke' }],
  proofs: [root],
});
```

行为：
- 如果 `cachedInvocationToken` 仍足够新鲜，直接复用。
- 如果剩余有效期不足，自动创建新的 Invocation Token。
- 如果 Session / Root 仍有效，这个过程不需要用户重新签名。
- 如果 Session / Root 已失效，才进入重新授权流程。

### 5.4 过期后自动刷新重试

`authUcanFetch` 会在可安全重试时自动处理 Invocation 过期：

```ts
import { authUcanFetch } from '@yeying-community/web3-bs';

const response = await authUcanFetch(
  'https://api.example.com/protected',
  {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ message: 'hello' }),
  },
  {
    issuer: session,
    audience: 'did:web:api.example.com',
    capabilities: [{ with: 'app:all:chat', can: 'invoke' }],
    proofs: [root],
  }
);
```

行为：
- 第一次请求如果成功，直接返回。
- 如果服务端返回可识别的 `UCAN expired` / 401，SDK 强制创建新的 Invocation Token。
- SDK 使用新的 Invocation Token 自动重试一次。
- 如果 Root / Session 仍有效，整个过程用户无感。
- 如果请求体是不可重放的流式 body，SDK 不会自动重试，避免重复消费 body。

这才是过期体验的主要兜底机制。

### 5.5 分类 UCAN 认证错误

```ts
import { classifyUcanAuthError } from '@yeying-community/web3-bs';

const info = classifyUcanAuthError(error);

if (info.shouldRefresh) {
  // 刷新或重建 token
}
```

可识别类型：
- `expired`
- `not-before`
- `unauthorized`
- `forbidden`
- `invalid-token`
- `unknown`

`UCAN expired (trace id: xxx)` 会被识别为：

```ts
{
  type: 'expired',
  retryable: true,
  shouldRefresh: true
}
```

## 6. WebDAV 自动初始化中的有效期配置

`initWebDavStorage` 支持为 invocation token 配置有效期和 skew：

```ts
import { initWebDavStorage } from '@yeying-community/web3-bs';

const storage = await initWebDavStorage({
  baseUrl: 'https://webdav.example.com',
  prefix: '/dav',
  audience: 'did:web:webdav.example.com',
  appId,
  capabilities: [{ with: `app:all:${appId}`, can: 'write' }],
  invocationExpiresInMs: 60 * 60 * 1000,
});
```

行为：
- 如果缓存 token 已过期或进入 skew 窗口，SDK 会重新签发 invocation token。
- 如果 Root / Session 仍有效，重新签发不需要用户重新签名。
- 如果 Root / Session 已过期，才需要走更上层的授权重建。

## 7. 推荐配置

| 场景 | Invocation TTL | 请求前判断 | 说明 |
| --- | --- | --- | --- |
| 普通接口请求 | 默认 1 小时 | 默认 skew 即可 | 正常情况下无感复用或换新 |
| WebDAV 小文件读写 | 默认 1 小时 | 默认 skew 即可 | 过期后由 SDK 自动刷新重试 |
| AI 流式对话 | 默认 1 小时 | 默认 skew 即可 | 过期后由 SDK 自动刷新重试；极长任务应使用任务 ID 恢复 |
| 长任务 / 批量任务 | 默认 1 小时或按需更长 | 默认 skew 即可 | 如果任务极长，应改为服务端任务票据 |

## 8. DApp 集成建议

请求前：
- 使用 SDK 默认 skew 判断是否复用旧 Invocation。
- 如果 token 已过期或即将过期，SDK 应静默刷新或重建 Invocation。
- 不要只用 `exp > now` 判断，更不要把“剩余有效期不足”直接暴露成用户错误。

请求中：
- 流式请求开始后不要频繁重试同一请求，避免重复消耗。
- 如果服务端支持任务 ID，应优先恢复任务结果，而不是重新执行。

请求失败后：
- 使用 `classifyUcanAuthError` 判断错误。
- `expired` / `invalid-token` / `unauthorized` 可以刷新 Invocation 后重试一次。
- `forbidden` 通常是能力不足，不应盲目重试。

账户变化后：
- 清理 access token。
- 清理 UCAN session。
- 重新建立 Root / Session / Invocation。

## 9. 产品体验建议

用户不应该看到“token 过期导致本次请求失败但已经消耗资源”的结果。

推荐体验：
- 请求前静默检查 token 是否过期或即将过期。
- token 已过期或即将过期时静默刷新 Invocation。
- 需要钱包签名时，明确提示用户“需要重新授权”。
- 钱包弹窗被遮挡时，重复点击只聚焦已有弹窗，不重复发起签名。
- 长流式请求失败后，如果能通过任务 ID 恢复结果，优先恢复；否则再提示用户重试。

## 10. 服务端配合要求

服务端应返回可分类的错误信息：

```json
{
  "error": {
    "message": "UCAN expired",
    "type": "auth_error",
    "code": "UCAN_EXPIRED"
  }
}
```

建议：
- 401：认证缺失、token 无效、token 过期。
- 403：认证有效但 capability 不足。
- 错误 message 或 code 中明确包含 `UCAN_EXPIRED` / `UCAN_INVALID` / `UCAN_FORBIDDEN`。
- 长任务接口尽量返回任务 ID，避免前端因网络或 token 过期重复消耗。
