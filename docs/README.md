# 文档导航

本文档目录用于回答三个问题：

1. 这个库到底是什么，适合什么场景？
2. 前端 DApp 应该从哪个能力入口开始接入？
3. 移动端、中心化 UCAN、WebDAV 这些扩展能力该怎么选？

## 推荐阅读顺序

- [职责复评](/root/code/web3-bs/docs/responsibility-review.md)
- [定位与能力边界](/root/code/web3-bs/docs/positioning.md)
- [快速上手](/root/code/web3-bs/docs/quickstart.md)
- [完整设计说明](/root/code/web3-bs/docs/sdk-design.md)

## 按主题阅读

- 钱包 Provider 发现、账号选择、签名：见 [完整设计说明](/root/code/web3-bs/docs/sdk-design.md)
- SIWE 登录、JWT 刷新、鉴权请求：见 [快速上手](/root/code/web3-bs/docs/quickstart.md)
- UCAN 多后端授权、WebDAV 存储：见 [快速上手](/root/code/web3-bs/docs/quickstart.md) 和 [完整设计说明](/root/code/web3-bs/docs/sdk-design.md)
- 基于钱包协议文档重新看职责边界：见 [职责复评](/root/code/web3-bs/docs/responsibility-review.md)
- 移动端无插件方案选型：见 [移动端认证方案总览](/root/code/web3-bs/docs/mobile-auth-options.md)
- 中心化 UCAN（无插件移动端 / demo 路线）：见 [中心化 UCAN 方案](/root/code/web3-bs/docs/mobile-auth-central-ucan.md)

## 面向谁

- DApp 前端工程师：需要统一接入钱包、登录、授权、存储
- 钱包 / 后端联调工程师：需要明确 SIWE、UCAN、JWT 的前后端交互边界
- 移动端方案设计者：需要在“钱包插件不可用”的前提下选择替代方案
