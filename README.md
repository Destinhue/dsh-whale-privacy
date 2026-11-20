# dsh-whale-privacy

给 DSH Agent 的**受众感知隐私闸门**：私聊里的事实，默认进不了群聊和公开评论。

## 它解决什么

一个真实场景：

1. 私聊里用户说：“我住朝阳区，电话 138…，别告诉别人。”
2. 群聊里有人问：“你住哪？”
3. Agent 的记忆插件把私聊记忆召回，模型顺手在群里回答。

`dsh-whale-privacy` 在两层上拦住它：

- **外发闸门**：`tools/pre-execute` 看到外发工具（`*send*message*`、`*comment*`、`*publish*`…）时，从参数里的 `group_id`/`peer_id`/`comment` 推断受众；群聊/公开/未知受众一旦包含私密短语、密钥、本机路径或（可配的）PII，直接拒绝。
- **受众化记忆**：`privacy_remember` 把事实存进 AES-256-GCM 加密的私密库，并标注 `private`/`group`/`public`；`privacy_recall` 只返回当前受众允许的事实。

另附：工具结果脱敏、哈希链审计、system prompt 隐私规则。

## 安装

在 DSH 里用插件管理器安装本地 bundle：

```bash
# 由 DSH 的 plugin_manager 执行，等价于：
# install_bundle target=/path/to/dsh-whale-privacy
```

或在 `~/.dsh/profiles/<profile>/cordis.patch.yml` 里检查是否已有：

```yaml
- insert:
    - id: dsh-whale-privacy
      name: dsh-whale-privacy
```

安装后新会话里应出现 6 个工具：`privacy_status`、`privacy_scan`、`privacy_remember`、`privacy_recall`、`privacy_forget`、`privacy_audit`。

## 配置

默认值在 `lib/config.js` 的 `DEFAULTS`。要覆盖，在 profile 的 patch 条目上加 `config`：

```yaml
- id: dsh-whale-privacy
  name: dsh-whale-privacy
  config:
    action: deny          # deny | ask
    pii: block            # 默认 warn；公开场景建议 block
    paths: block
    secrets: block
    privateTerms: block
    unknownAudience: warn # block | warn | allow
    resultRedaction: secrets # off | secrets | secrets-pii
    outboundTools:
      - '*send*message*'
      - '*comment*'
      - '*publish*'
      - '*reply*'
    dataDir: ''           # 默认 $DSH_HOME/whale-privacy
```

受众推断规则：

| 信号 | 受众 |
| --- | --- |
| 工具名/参数含 `group_id`、`room_id`、`chat_id`、`群` | group |
| 工具名/参数含 `comment`、`post`、`publish`、`dynamic` | public |
| 工具名/参数含 `peer_id`、`private`、`dm`、`recipient` | private |
| 都没有 | unknown（默认只警告，可配成 block） |

`private` 只拦密钥和本机路径；私密短语在私聊里正是要说的内容。

## 工具

| 工具 | 用途 |
| --- | --- |
| `privacy_status` | 策略、加密库条数、审计链健康、计数器 |
| `privacy_scan` | 干跑一次外发检查；只返回类别/数量，不返回原文 |
| `privacy_remember` | 存私密事实，标注 audience/scope/terms |
| `privacy_recall` | 按当前受众召回；私密的不会出现在群聊 |
| `privacy_forget` | 按 id 删除 |
| `privacy_audit` | 读哈希链审计（不含正文） |

## 与其他记忆插件集成

本插件**不能**阻止另一个插件直接往 system prompt 注入私聊记忆。正确做法是把召回收敛到本插件：

```js
const privacy = ctx.get('whalePrivacy');
const { allowed } = privacy.recall({ audience: 'group', scope: `qq:group:${groupId}`, query });
// 只把 allowed 注入当前 turn；private 事实不会出现在这里
```

如果继续用 `dsh-familiar-memory` / `dsh-self-improved`，请确认它们的召回按会话/受众隔离，或把本插件作为唯一召回入口。

## 边界

- 不做语义级 DLP：模型改写“朝阳区”为“东边那个区”时拦不住。
- 不改 session：一个受众一个 session 是部署责任。
- 只脱敏工具结果里的文本块；`value`、图片、附件、语音不处理。
- 不替代发布前人工审计：`~/.dsh/sessions/*.zstd` 仍是明文。
- 审计只存类别/数量，不存原文。

完整分析见 [`docs/威胁模型.md`](docs/威胁模型.md)。

## 测试

```bash
node --test test/*.test.js
```

当前 18 项：检测器、配置/受众推断、加密库、审计链、插件装配与 pre/post 钩子。

## 数据

- `$DSH_HOME/whale-privacy/vault.enc`：AES-256-GCM 密文。
- `$DSH_HOME/whale-privacy/vault.key`：32 字节密钥（0600）；也可用 `DSH_WHALE_PRIVACY_KEY` 环境变量。
- `$DSH_HOME/whale-privacy/audit.jsonl`：哈希链，无正文。

## License

MIT
