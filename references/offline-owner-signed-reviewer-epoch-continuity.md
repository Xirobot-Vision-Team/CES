# EC358 — 离线真签 Reviewer Key 纪元、所有者授权与撤销连续性协议

## 功能与信任边界

EC358 是**单轮新增的只读离线审计能力**，不替换 EC357，不自动生成私钥、不签发用户事件、不联网、不读取操作系统根证书仓库、不写 Provider/CAS/WORM。每次审计都**实际运行** `EC357.audit`，从 EC357→EC356→…→EC337 验旧签名/整 SHA 与未决事实，而不是信任随意提供的旧 JSON 结果。来自旧 `source_review` 的 `source_id`、reviewer 签名公钥整 SHA 与原 signed review SHA，加上本次 EC357 canonical result SHA，必须由每个 EC358 纪元事件真正签入。

EC358 支持每来源至多 **8** 个原事件、至多 **2** 个来源：`issue(epoch=0)`、`rotate(old→new)`、`revoke(old→null)`。每条事件由**独立在 bundle 外调用方 SHA-pinned 的所有者 Ed25519 公钥**真签，`issue` 再由当前 reviewer 真签，`rotate` 必须另验旧 reviewer 与新 reviewer 的**不同域**真签，`revoke` 必须由旧 reviewer 真签。各来源各一把不同 owner key，不得与 EC351/352 的已有签名角色、EC353 log/witness、EC354 auditor、EC356 root/channel、EC357 reviewer 混用。跨来源 reviewer key 不得重用，也不允许把任何新 owner key 换个路径冒充 reviewer key。

外部 root/owner 的原始整 SHA 固定与本地 Ed25519 真签，**只是给定公钥与提交者的密码学关系**。缺失独立可信分发链、可核验的官方制度/证书授权、可信时间、物理保管和全局最新头的情况下，**不证明**组织官方身份、法律独立性、机构撤销事实、历史发生时间或全球完整性。EC358 不声称实现官方根身份认证；即使所有本地事件一致，合法输出仍为 **exit code 2 / `_unresolved`**，不能作为上游 `Quality=true` 或最终验收证据。

## 命令

- 独立只读：`python -I -B scripts/ces_cas_reviewer_epochs.py derive-reviewer-epoch-handoff [EC357 原字段]`
- 独立只读：`python -I -B scripts/ces_cas_reviewer_epochs.py audit-reviewer-epochs [EC357 原字段] [EC358 新字段]`
- 统一固定隔离：`python scripts/ces_next.py audit-reviewer-epochs DeliveryAudit AuditReviewerEpochContinuity [同一原字段和新字段]`

`EC357 原字段` 包含 EC351/352 的连续签名原件/根/pin 列表、EC353/354/355/356 的 bundle 和 root SHA、EC357 的 source bundle 与两把来源审阅公钥 SHA、各层严格 `*_evaluation_utc`。不可省略原祖先必填项。新增 audit 必需 `--reviewer-epoch-evaluation-utc YYYY-MM-DDTHH:MM:SSZ`，其 UTC 是**调用方自报而非可信钟**。其他新增成对可选字段（缺失则只得未决结果，不能升级）：

| CLI 参数 | 作用 |
|---|---|
| `--reviewer-epoch-bundle-file` + `--expected-reviewer-epoch-bundle-sha256` | 实际重读 whole SHA-pinned canonical JSON 纪元 manifest |
| `--owner-a-public-key-file` + `--expected-owner-a-public-key-sha256` | 独立于 bundle 的来源 a 所有者 32 字节 Ed25519 公钥原件和整 SHA |
| `--owner-b-public-key-file` + `--expected-owner-b-public-key-sha256` | 来源 b 独立所有者同类 pin；两来源不得复用 |
| `--minimum-a-epoch` / `--minimum-b-epoch` | 调用方外部保管的非负最小纪元，范围 0–7；未提供则未决 |
| `--expected-a-head-event-sha256` / `--expected-b-head-event-sha256` | **bundle 外**独立保存的期望已签链头整原 SHA；缺失/不符不能通过连续性核对 |

**注意：** 仅独立保存并明确提供的最低 epoch/head SHA 能在本次本地提供一定防回滚锚点；同一 ZIP/同一来源凭空自称的“当前链头”不能替代外部 pin。外部 head 不在真实验签的所有可见事件中时拒绝，而不是偷偷选择另一头。

## canonical 严格签名原件

全部 JSON 必须 `UTF-8`、严格 canonical JSON（键排序、紧凑编码），拒绝重复 key、未声明字段、非 canonical 字节；全部 SHA 为小写 64 位 hex（非全零）；全部非空签名为小写 128 hex。事件 body（**不包含**三项签名字段）完整签入三个**分别域隔离**消息：

```
owner:    b'CES/EC358/ReviewerEpoch/Owner/v1\x00'            + canonical_json(body)
previous: b'CES/EC358/ReviewerEpoch/PreviousReviewer/v1\x00' + canonical_json(body)
current:  b'CES/EC358/ReviewerEpoch/CurrentReviewer/v1\x00'  + canonical_json(body)
```

`event_original` 文件精确字段：

```json
{
 "schema":"ces.ec358.signed_reviewer_epoch_event.v1",
 "slot":"a",
 "source_id":"external_review_a",
 "claimed_owner_id":"alleged_legal_owner_a",
 "owner_public_key_original_sha256":"<owner-raw-public-sha>",
 "parent_ec357_canonical_result_sha256":"<freshly-replayed-parent-result-sha>",
 "parent_source_review_original_sha256":"<actual-EC357-source-signed-review-original-sha>",
 "epoch":0,
 "previous_event_original_sha256":null,
 "operation":"issue",
 "previous_reviewer_public_key_original_sha256":null,
 "current_reviewer_public_key_original_sha256":"<current-reviewer-raw-public-sha>",
 "issued_utc":"2026-10-26T02:00:00Z",
 "expires_utc":"2026-10-28T02:00:00Z",
 "signature_owner_ed25519_hex":"<actual-Ed25519-owner-signature>",
 "signature_previous_reviewer_ed25519_hex":null,
 "signature_current_reviewer_ed25519_hex":"<actual-Ed25519-current-reviewer-signature>"
}
```

`issue`：epoch 0、无前驱/旧 signer、新 reviewer 与 owner 分域双签；`rotate`：epoch=old+1、旧前驱 original SHA 与旧 reviewer SHA 必须匹配，**旧、新、owner 三者真签**、新旧公钥 SHA 不同；`revoke`：epoch=old+1、仅 old+owner 真签，`current_reviewer...=null`，不得有新 reviewer 签名、不得有后代。每项事件有效时间区间不得反向、最长 90 天；本地按调用方时间检查头过期/未来/签发距今超过 30 天及签名分支的时序倒退，异常仅降低为未决，不宣称可信 UTC。

Manifest schema 为 `ces.ec358.pinned_reviewer_epoch_bundle.v1`，精确 `sources`（最多 2）数组；每项精确字段：

```json
{
  "slot":"a",
  "owner_public_key":{"path":"/trusted-source-a/owner.raw","sha256":"<sha>"},
  "events":[
     {
       "event_original":{"path":"/evidence/epoch-0.json","sha256":"<sha>"},
       "previous_reviewer_public_key":null,
       "current_reviewer_public_key":{"path":"/key/current.raw","sha256":"<sha>"}
     }
  ]
}
```

两个 `owner_public_key` 必须逐项严格等于 bundle **外**的独立调用方 pin。实际每一项签名来源 Ed25519 公钥原件按 path + SHA 重新打开，`old/new` 中 reviewer SHA 必须与签名 doc 对应；已经在 EC357 使用的签名公钥必须使用**原来的同一个文件 pin**（不能换名字复制）；新增 reviewer 公钥必须是另行提供的新原件。路径须绝对且非 symlink/祖先 symlink；新 owner / event / reviewer 不能是父原始文件的路径/硬链接，也不能跨新角色复用同 inode。离开前重读本轮和受保护父来源原件的 SHA，并复查 inode；不声称原子文件系统快照。

按**真实事件 SHA** 建图，不能通过索引顺序“造出”前驱。所有出现的签名 event 都必须验签并能够溯源到实际 issue；缺少任意签名祖先、无效链接/纪元跳跃、撤销后续接、坏签、重复事件直接拒绝（exit 3/4/5），不能把坏签悄悄忽略。在同前驱双 rotate、双 genesis、多终点、不同 signed owner label、跨来源相同 owner label 时，所有可见真签分叉都保留，任何单独签名头不能抹掉另一支；即使选中头没有异常，**观察到 fork 也只能得到未决**。选中头若落后于调用方 minimum epoch、有已见真实后代、与 EC357 reviewer 签名原件 SHA 不匹配，均显式报告回滚或 signer mismatch。

这些事件本身包含本次 EC357 canonical result SHA/签名 review SHA，是**针对本轮父证据的签名陈述**；即使签名中写了较早 `issued_utc`，也不能证明那天真实发生过签发或撤销。密钥来源及物理独立性还需来自确实可核验的链外权威材料，无法只靠两条本机签名证明。

## 输出优先级（全部加 `_unresolved`）

1. `ec358_parent_ec357_signed_custody_and_source_review_unresolved`
2. `ec358_missing_two_caller_pinned_owner_and_reviewer_epoch_heads`
3. `ec358_signed_reviewer_epoch_branch_fork_or_owner_collision_visible`
4. `ec358_signed_reviewer_revocation_terminal_visible`
5. `ec358_pinned_epoch_rollback_or_review_signer_mismatch_visible`
6. `ec358_issued_expiry_or_historical_clock_claims_stale_or_conflicting`
7. `ec358_two_real_signed_owner_reviewer_histories_official_identity_unproven`

异常的布尔状态并行保留（优先级高的 outcome 不删除低优先级的事实）；`owner_establishments` 给出各事件真 SHA/epoch/operation/predecessor、所有者签名声称、选择的调用方 head 与 minimum epoch、签名 reviewer 匹配事实；`channel_evidence` 继承各父 EC357 status 并叠加 EC358 整体 outcome；输出必须通过 `ces_next.py` 的固定子进程完整 JSON/退出码强契约。

## 实际开发验证事实与后续人工验证

新建 20 个不同的 synthetic owner / old reviewer / new reviewer Ed25519 真签案例，在分段五组运行里均获得 PASS（不是单次完整 20 例连续运行）。含真正三方轮换、双源签名 issue、terminal revoke、不存在前驱、双分叉、回滚下限、跨角色 key 复用、旧父撤销不能修复、错误双签、过期/未来时间，以及 `python -I -B` 固定统一入口。所有历史父层真实签名与完整原件重放，但未独立全套重跑父 EC357、EC356 以前的测试。EC356 历史 case24 仍 NOT_VERIFIED。EC317/318 深层 old fixture MOCK；原生 PS7/原 15 Smoke/Win/macOS/Git/CI/Provider/E63-E66、真实多机构法律/物理 custody、可信 UTC 和全球无隐藏分叉、remote CAS/WORM、最终人工验收均 NOT_RUN/NOT_PROVEN。EC249 INCOMPLETE、EC250 BLOCKED、B001 OPEN、Quality=false、final NOT_STARTED。所有合法结果一律退出 2 unresolved。
