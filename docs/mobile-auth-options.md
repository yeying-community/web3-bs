# 移动端 Web DApp（无钱包插件）认证方案总览

此文档是总览，详细落地流程请分别查看：

- `docs/mobile-auth-walletconnect.md`
- `docs/mobile-auth-embedded-wallet.md`
- `docs/mobile-auth-sso-webauthn.md`
- `docs/mobile-auth-central-ucan.md`
- `docs/mobile-auth-pc-binding.md`
- `docs/mobile-auth-accounts.md`

## 快速选择建议

- 必须保留链上身份 + UCAN：优先 WalletConnect（A），其次嵌入式钱包（B），或 PC 首次绑定（E）。
- 移动端体验优先：SSO/WebAuthn（C）。
- 只要快速落地：传统账号体系（F）。
- 想保留 UCAN 形式但接受中心化：中心化 UCAN 发行（D）。

## 决策问题

1) 是否必须保留链上身份与 UCAN？
2) 能否接受用户安装第三方钱包 App？
3) 能否接受中心化身份（SSO/JWT）？
4) 是否可接受首次 PC 绑定移动端？
