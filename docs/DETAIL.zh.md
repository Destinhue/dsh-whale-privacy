# 隐私闸门

给 DSH Agent 的受众感知隐私层。

- 私聊记忆默认只回私聊；群聊/公开外发前由 `tools/pre-execute` 检查。
- 6 个工具：`privacy_status`、`privacy_scan`、`privacy_remember`、`privacy_recall`、`privacy_forget`、`privacy_audit`。
- 私密库 AES-256-GCM 加密，事实带 `private`/`group`/`public` 受众标签。
- 审计为哈希链，只记类别与数量，不记原文。

适用场景：大肥鱼/QQ bot/B站评论/邮件等多渠道 Agent，尤其是“私聊记忆被群聊召回”的泄漏。

详见 `README.md` 与 `docs/威胁模型.md`。
