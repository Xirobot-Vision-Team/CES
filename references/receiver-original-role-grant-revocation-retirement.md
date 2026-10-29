# EC388 — 原 EC338/339 角色签名授权、挑战式 status/revocation 与 EC340 旧根退役接收协议

## 目的、来源优先级和安全边界

当前施工版 **V6.98/R388/EC388**，输入父基线 **V6.97/R387/EC387**。这是离线、只读、证据保守的**接收方协议**；不出具新的 issuer 身份、root 权限、合法撤销保证或全球已知状态。保留旧 EC339 原本用来审查 `active` 的原始校验；本轮在接受可信旧签名和有效 SHA 后，另以**历史观察**方式识别 `revoked`，不能将它传回操作授权接口。

执行顺序不可省略：`EC387 audit` → canonical result SHA → 精确打开旧 EC386/EC387 archive → 旧 EC386 认证的 EC341 manifest 第一跳、旧 policy/EC339 issuer roster 和签名根退役观察 → 四角色已认证 EC338 receipt/EC339 grant/原 active baseline status → 本轮补交的 original challenged status。父源缺失报告 unresolved，不得自造签名材料。EC353 sender-origin 标签禁止作为独立 receiver original。

## 命令

```sh
# 派生未签名的逐 epoch 原件库存（需要全部父层审计参数及本层必需参数）
python -I -B scripts/ces_cas_historical_retirement_archive.py derive-historical-ec339-retirement-inventory --help

# 对照独立保管人提供的库存及逐 epoch SHA/数量下限
python -I -B scripts/ces_cas_historical_retirement_archive.py audit-historical-ec339-retirement-archive --help

# 与完整父链相同的固定统一只读路线
python -I -B scripts/ces_next.py audit-historical-ec339-retirement-archive DeliveryAudit AuditHistoricalEC339RetirementArchive --help
```

除**全部继承的 EC387 及更早父层强制参数**（其中含各层 audit-only 外部 SHA）外，本轮严格增加这些新字段；CLI 使用同名 kebab-case 选项：

| 接收参数 | 类型 | 约束 |
|---|---|---|
| `historical_ec339_retirement_revocation_archive_bundle_file` | 字符串 | 本层原始 archive 规范绝对路径 |
| `expected_historical_ec339_retirement_revocation_archive_bundle_sha256` | SHA-256 | 整个 archive 文件摘要 |
| `historical_ec339_retirement_role_inventory_shas` | 每 epoch SHA 列表 | 角色/actor/grant/status 原始库存独立留存 SHA |
| `historical_ec339_revocation_transition_inventory_shas` | 每 epoch SHA 列表 | 撤销转换/挑战状态清单独立留存 SHA |
| `minimum_historical_ec338_signed_actor_receipt_counts` | 每 epoch 整数列表 | 0..8，每通道四个角色真实 receipt |
| `minimum_historical_ec339_retirement_status_counts` | 每 epoch 整数列表 | 0..8，每通道至多四个覆盖退役瞬间的真实 signed status |
| `minimum_historical_ec339_signed_revocation_transition_counts` | 每 epoch 整数列表 | 0..8，每通道每角色首次 signed revoked 转换至多一个 |
| `expected_retained_historical_ec339_retirement_revocation_inventory_sha256` | SHA-256 | 仅 audit：接收方外部预留的**整份未签名库存** SHA |

每个重复参数提供与 `historical_directory_root_shas` 相同的 1–3 个 epoch 值；两个 channel 需要按原真实父 archive 的严格字典顺序排列。不能自造缺省 SHA 或重复计数充数。`derive` 不需要最后的 audit-only 库存 SHA；所有合法结果 `exit 2 unresolved`，拒绝 `3/4/5`。

## 本层接收 archive 严格 JSON Schema v1

根对象**只能包含**下列五个属性；固定 schema：

```json
{
  "schema": "ces.ec388.receiver_historical_old_ec339_issuer_revocation_archive.v1",
  "parent_ec387_canonical_result_sha256": "<EC387 本次真实执行结果之 canonical JSON SHA-256>",
  "ec387_historical_rotation_archive_original_sha256": "<父 EC387 原 archive 整文件 SHA-256>",
  "claimed_directory_lineage_id": "<与认证的旧 EC386/EC387 根完全一致的 lineage ID>",
  "epochs": [
    {
      "epoch_index": 0,
      "channels": [
        {
          "tsa_channel_id": "<与父 EC386/EC387 对应通道完全相同>",
          "ec338_policy_original": {"path": "<真实已认证绝对路径>", "sha256": "<64 hex>"},
          "ec339_issuer_roster_original": {"path": "<真实已认证绝对路径>", "sha256": "<64 hex>"},
          "ec340_successor_roster_original": {"path": "<真实已认证绝对路径>", "sha256": "<64 hex>"},
          "ec340_retirement_observation_original": {"path": "<真实已认证绝对路径>", "sha256": "<64 hex>"},
          "ec339_role_retirement_reviews": [
            {
              "role": "sender",
              "actor_receipt_original": {"path": "<父 EC387 已认证完整原件>", "sha256": "<64 hex>"},
              "issuer_grant_original": {"path": "<父 EC387 已认证完整原件>", "sha256": "<64 hex>"},
              "baseline_status_original": {"path": "<父 EC387 已认证完整原件>", "sha256": "<64 hex>"},
              "additional_challenged_status_originals": [
                {
                  "signed_status_original": {"path": "<旧 EC339 原始 Ed25519 signed status 文件>", "sha256": "<64 hex>"},
                  "verifier_challenge_sha256": "<64 hex，与该签名 claim 相同>",
                  "evaluation_utc": "<RFC3339 UTC，落在 signed status window 内>"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

真实每通道 `ec339_role_retirement_reviews` 必须**恰好四项**，严格按 `old340.ROLES`（sender、carrier、receiver、witness）排序（以代码实际的固定旧角色表为准）；每项 0–2 份新的签名 `additional_challenged_status_originals`。以上示例只展开第一角色及第一份额外 status，不能把示例直接当作有效完整 archive。四个父源引用以及 policy、issuer roster、successor、retirement observation 的**路径和 SHA 必须与认证的父原件完全一致**；不是重新上传相同字节就能变成旧登记源。

若真实父 EC387 通道没有 `ec340_legacy_policy_original`，本通道必须用 `null` 填写四个对应的 `*_original` 字段、`ec339_role_retirement_reviews: []`，并且对应 EC386 source 没有旧 EC341 manifest；输出明确的缺源 unresolved，不能凭自签文件补全。

## 原件校验、状态解释和检测规则

1. **签名与旧授权域：**原始旧 EC338 policy、四 actor signed receipt 的前序 SHA、签名/签署时间，旧 issuer roster、角色 grant 签署窗口与真实原 `baseline status` 全部用原 EC338/339 校验器复核。额外 status 仍使用旧 EC339 签名 domain、旧 issuer 公钥、`grant_original_raw_sha256`、`transfer_id/issuer_id/grant_id/role`、原签名挑战和 24 小时有效期规范。
2. **原退役分界由先验旧根确定：**从被 EC386 认证的 EC341 manifest 首个签名轮换 hop 及 EC340 signed retirement observation 取 `effective_utc`；判断 status `as_of_utc <= effective_utc < expires_utc` 才是**真正覆盖瞬间**的挑战式状态。仅在退役之后声明的 revoked 不能充当当时覆盖证明；但可成为可见的后续撤销声明证据。某角色缺覆盖原件，明确 unresolved。
3. **grant 并非撤销：**`grant.not_before_utc <= effective_utc < grant.not_after_utc` 是原授权窗口的历史比较，不能证明新 epoch 新授予。根退役不会自动使所有旧 grant 在其原 signed window 中立刻撤销；反之旧 signer 在退役后出具一份声称 `active` 的 status，也不能赋予新根授权。
4. **一次真正可见的状态转换：**确认 baseline 为旧 verifier 正常接受的 `active`，后续第一份完整签署的 `revoked` 记录为一次角色撤销转换（无论其原 status 时窗跨越退役或只声称退役之后）；重复 revoked 不算多次。`revoked_effective_utc` 不能晚于 `as_of_utc`，也不能早于原 grant 的 `issued_utc`。按声明时间（不冒充可信真实发行时间）严格递增；后继 active 是 ABA/矛盾而不是默许恢复授权。
5. **双渠道和跨 epoch：**同通道后续 epoch 的源 SHA、root retirement、grant/actor/baseline 不得改写，additional statuses 必须为原顺序**追加**。两个通道四角色的旧授权 SHA 不同、相同 as-of 时刻不同签名 state、或者一个通道 observed revoked 后另一通道 later active，均为 adverse/unresolved。接收方只报告**已看见的**状态/冲突，不保证全球 CRL/OCSP 完整性。
6. **反欺骗与读一致：**原始文件绝对规范路径、整文件 SHA、严格 exact-key、签名验证、late reread、EC353 sender-source denylist、每 epoch 接收方独立库存 SHA 和外部签名证据下界阻止误把自报副本当作认证父源。外部预留 SHA 也不等于可信 offsite 保管已实证。

## 尚待统一验收

本地 **28/28** 聚焦用例通过，真实本地签发的旧格式 Ed25519 receipt/grant/status 支持了新功能；**四项外层 engine case 的 EC387→EC369 父结果 MOCKED，继承旧 EC317/318 祖先 fixture 亦 MOCKED**。尚未具备**真实独立外部完整 EC387→EC369 生产档案**、原 EC339→EC337 未 mock 的第三方历史、双通道外部独立保管与完整撤销库、法律授权及密钥主体分离、实际可信 UTC 和物理冻结证据。本地 Python 不推断这些事实。统一验收保留原 PS7/15 Smoke、Windows/macOS、Git/CI、Provider E63–E66 和用户终验。原生 PowerShell V4.60/R150 未动；EC249/250/B001/Quality 门保持原样。
