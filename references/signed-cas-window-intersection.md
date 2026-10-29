# EC313 — 两份 EC312 已签 CAS 窗口的原件交集核验（只读）

## 使用边界

这不是一个 CAS 写入器或新的 signer。本模块从 **独立于被审计数据** 的私有规范 JSON manifest 和包外整字节 SHA 开始，读取两份**不同** EC312 manifest 及其分别原样钉住的 2–8 个 CAS issuer + 两名 Ed25519 observer 的证据链；对每个窗口实际调用未经修改的 `EC312.evaluate()`，逐次运行 `EC309 → EC308 → EC307 → … → EC294` 的原始签章/ACK/ZIP 验证。旧 EC312 报告或上次的 `PASS` 不可输入替代真签原件。

两个 EC312 子窗口可以使用相同或不同的独立 observer 身份（最多四把不同的 observer 公钥）。**同一 observer ID** 跨窗口要求**同一公钥**；同一公钥不能改名复用；不在 EC313 推断密钥轮换授权。CAS authority 身份、公钥、namespace 与经真实签名重算的 registry ID 必须和本轮另外单独指定的信任根一致。

### 完整外部 manifest 结构

必须存成单个 owner-private **0700 父目录内 0600 正规单硬链文件**，规范 JSON + LF，禁止软链/重链/非法字段或重复 JSON key，记录原件所有 SHA 值来自包外独立保存的 trusted 工作记录。示意中 `...` 必须替换为真实值，**不提供私钥**：

```json
{
  "schema": "ces.ec313.cross_window_signed_cas_intersection_manifest.v1",
  "cas_authority_id": "independent_cas_site",
  "cas_authority_public_hex": "<64-char-lowercase-real-ed25519-public-hex>",
  "cas_store_namespace_id": "private_cas_namespace",
  "expected_registry_id": "example_registry",
  "windows": [
    {
      "window_id": "left",
      "manifest_file": "/absolute/private/ec312-left.json",
      "expected_manifest_sha256": "<64-char-lowercase-external-raw-sha>"
    },
    {
      "window_id": "right",
      "manifest_file": "/absolute/private/ec312-right.json",
      "expected_manifest_sha256": "<another-external-raw-sha>"
    }
  ]
}
```

窗口 ID 要各自独立且字典序升序；两份 EC312 原 manifest 整原字节 SHA **不得相同**。它们的内容仍严格采用 `references/two-independent-signed-cas-observer-windows.md` 原协议，内含实际绝对私有路径、每份独立 CAS receipt/fork case/fork evidence/readback 整字节 SHA 与角色 nonce。每个子窗口仍至少两份、至多八份不同真实已签 issuer 回执，两条原 observer 窗口各自满足前驱 SHA/seq/revision。

### 运行

```bash
# 读操作；不保存报告
python3 scripts/ces_cas_intersection.py verify \
  --manifest-file /absolute/private/ec313-root.json \
  --expected-manifest-sha256 EXTERNALLY_PINNED_FULL_RAW_SHA

# 仅独立 CLI verify 可通过 O_EXCL 0600 fsync 新建一份无私有源路径的审计报告
python3 scripts/ces_cas_intersection.py verify \
  --manifest-file /absolute/private/ec313-root.json \
  --expected-manifest-sha256 EXTERNALLY_PINNED_FULL_RAW_SHA \
  --out /absolute/private/new-ec313-audit.json

# 第二位操作员由包外独立获取报告原始 SHA，重新重放所有真正 Ed25519 原签章
python3 scripts/ces_cas_intersection.py verify-report \
  --manifest-file /absolute/private/ec313-root.json \
  --expected-manifest-sha256 EXTERNALLY_PINNED_FULL_RAW_SHA \
  --audit-report-file /absolute/private/new-ec313-audit.json \
  --expected-audit-report-sha256 INDEPENDENTLY_OBSERVED_SAVED_REPORT_RAW_SHA

# 统一 console 必须指定唯一允许的 Action/Mode，且只能只读 verify
python3 scripts/ces_next.py audit-intersection \
  DeliveryAudit ReconcileOverlappingSignedCasWindows \
  --manifest-file /absolute/private/ec313-root.json \
  --expected-manifest-sha256 EXTERNALLY_PINNED_FULL_RAW_SHA
```

`--out`、审批、签名、实际 CAS API / Host/Provider 权限均不可通过 console 获得；`verify-report` 只属于独立可运行 CLI。任意可认证签章矛盾、缺交集或无验证前史均 **不选择赢家**。

## 对账语义：共享的是原 issuer 签名回执，不是摘要报告

- **原件共享**：两个窗口只有当完整 EC308 原 issuer receipt 的独立原字节 SHA 相同，才算一份可重验的**交集锚**；另外逐字段确认两边实际重验出来的 EC307 case/evidence、CAS claim/nonce/parent/outcome/revision/head 相等。一个窗口可以有非共享头/尾，但整个合并窗口按真正 Ed25519 已签 issuer revision 从小到大必须连续，并且每一下一份 issuer signed CAS parent `(revision,head)` 精确等于上一份已签结果。
- **同 CAS revision 的真签矛盾**：两窗口各自的 issuer **和** observer 的所有原签名状态 `(revision,head)` 全部交叉对照；相同 revision 两个不同 signed head 立即 `exit=2`，不自动称哪边是真实 CAS 状态。对同一 observer ID/公钥同一 sequence 签署不同完整 readback 原件（即使头相同）也 `exit=2`。
- **双发行和 nonce**：同 CAS revision 出现不同 issuer 已签 receipt，即使 claim head 恰巧相同也不得合并成同一裁决；不同角色/不同源原件重复使用同一 nonce 亦被拒绝选赢家。跨窗口**同一份**原件的合法重放允许复用同一 SHA/nonce，不能将其误判为重放攻击。
- **非创世外部 boundary**：仅当另一窗口确实含有该 observer 相同 sequence 的真实已签 readback 时，用那个真实原字节 SHA、revision、head 校对边界。不匹配 `exit=2`；若另一窗口缺少该前史，保持为**不曾验证的 opaque**，不得凭空生成签名。创世边界只表示输入从创世开始，并不单独证明真实外部系统初始状态。
- **零交集**：即使两段 CAS issuer 声明碰巧在 revision/head 上相邻，**没有共同的原签 issuer receipt** 仍 `exit=2`；不可把序号连续或 opaque boundary 当成真实已认证交接。报告给出 `left_only/right_only`、重放并集数量和已签异常、可对账的边界位置。

报告优先分类依次为 `cross_window_authentic_signed_revision_head_or_sequence_conflict`、`cross_window_distinct_signed_issuer_sources_claim_same_revision_or_nonce`、`one_or_both_original_signed_observer_windows_not_compatible`、`cross_window_opaque_boundary_contradicts_replayed_signed_predecessor`、`no_common_original_signed_issuer_receipt_cross_window_continuity_unproven`、`cross_window_signed_issuer_union_parent_chain_discontinuous`；都为 `exit=2` / `candidate=null`。唯有**两个子窗口均通过 EC312 真原件重验**、真正存在共同 issuer SHA、所有已签身份/sequence/状态/nonce 无交叉异常、合并 CAS parent 连续时 `exit=0` 且候选仅为**本次窗口内相容签名声明**。

`permission_denied=3`、`invalid_input=4`、`unavailable=5` 为严格拒绝而非 `exit=2` 的真签冲突结论；使用未经验证签名、伪造原 SHA、自回显错误来源、字段缺失/过量、路径私有权限错误/非规范文档均不作为有效“签名冲突”证据。

## 实际验证界限和未闭环

- 完整读取并验证的只是**用户给出的有界集合**：两份原 EC312 window manifest 各含 2～8 份有序不同 CAS decisions；不存在证明窗口前史、遗漏窗口、未提交分支或真实全网 latest 的机制。
- 独立 Ed25519 公钥 **不证明**两个持钥者属于两个独立法律实体、已获权、持钥安全、nonce 全球唯一、可信 UTC、确实观察了同一真实物理存储系统或 CAS/WORM 写入线性化。
- 没有生产网络/CAS/Provider/Inbox 交互、写入、签发或原 Router/PowerShell 权限扩大；没有修复 EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`，也不能将全局 Quality PASS 改为 true。
- 完整原 EC294 之前的用户/组织证据托管和真实生产数据仍须最后在用户协助下统一验证；Windows/macOS/PowerShell7 原15 Smoke、Git/CI、E63–E66 等本轮不冒称已执行。
