# EC310 — 有界观察历史签章重验协议与操作手册

## 目标与不变量

EC309 能验证**当前**回读已签原件，却只核对外部给出的上一观察 `(seq,整字节SHA,observed revision)`，未重新验签前任原件。EC310 增加一个**只读、有界 1～16 条历史前驱窗口**，逐条从原始 0600 文件读入 EC309 JSON、验证独立 raw SHA、独立查询 nonce、同一个**已重验的 EC308 原始 CAS 裁决**、同一 observer key/身份/namespace，以及每条前驱的 Ed25519 域分离真签名和连续链接。最新 EC309 记录必须自己经旧代码完整重演 EC308→EC307→EC294 原签名、三方来源等，不能仅传旧 audit report 布尔值。

这是**同一 EC308 原裁决、同一观察者、同一 namespace** 的有界连续记录协议；**不是**跨任意 CAS 裁决或跨组织签名的通用全球历史验证器。原 EC309 记录格式/签章/域常量不改，旧客户端继续可用。窗口前的非创世锚没有历史原件：只能声称“本窗口验过”，不能声称创世以来完整验过。即使窗口从创世开始，仍只证明**所提交文件的签章链**，不能证明不存在未提交的另一份有效分叉/记录或真实外部存储行为。

## 必须独立给定的信任输入

1. 与 EC309 完全相同的**原始 EC307 case、已签 fork evidence、EC308 已签 CAS receipt、最新 EC309 readback** 四份文件路径 + **四份完整 raw SHA**；原 EC308 CAS authority 身份、公钥、原请求 nonce、父 revision/head；最新 observer 身份、公钥、namespace、最新 query nonce、最新前任 `(sequence, SHA, observed_revision)` 全部沿用，**不得从随文件收到的 JSON 中自选这些值**。
2. `--previous-readback FILE RAW_SHA256 NONCE_SHA256` 至少 1 次，至多 16 次，**按签名 readback_sequence 从小到大**排列。三元组中的 `RAW_SHA256` 必须是该份**完整 readback 原字节**由包外渠道交叉确认的 SHA，`NONCE_SHA256` 必须由可信请求发起方独立记录，而不是直接复制签名 claim；各次请求 nonce 不得与同窗口其他请求、原 CAS 请求及最新请求重复。还不等于具备可信 UTC、全网 nonce 唯一性、实时签发时间。
3. `--boundary-sequence N --boundary-raw-sha256 SHA --boundary-observed-revision REV`：窗口最早记录**之前**的一次外部锚。创世：`0` / 64 个 `0` / `none`；非创世：正整数 N、单独持有的完整上一条 readback SHA、该条曾声称的 observed revision，**此更早记录本轮不验签**，报告永远标明历史边界。不允许伪造“从创世证明”的字段。
4. 最新记录原先附带的 `--expected-previous-readback-sequence/sha256/observed-revision` 必须等于**窗口最后一条经完整原件验签的前驱记录**，其与最新记录的 signed previous link 也必须完全一致。自动重算外部 trust 锚不等于外部独立指定，二者需同时核对。

所有 JSON 文件均通过旧 EC306 读取器进行 0700 owner-private 父目录、0600 普通独立硬链、拒绝 symlink、单链接、规范 UTF-8 JSON+LF、完整 SHA 与稳定 inode 前后检查；输出报告不含本机路径/私钥。Linux/Unix 语义在新窗口中继承旧实现；NFS、恶意根目录竞态、Windows/macOS 和硬件故障不视为已认证。

## 逐条检查与重要限制

- 强制先检查历史窗口输入数量、SHA/nonce 去重和创世或非创世边界合法性，再完整运行旧 EC309 **当前一条** `evaluate`；它会重新执行 EC308 真签 CAS 机关、EC307 真签 fork 与 EC306→EC294 的底层原始签名和 ACK/ZIP 验证。本轮不以旧审计 JSON 代替这一重验。
- 逐条使用旧 EC309 `READBACK_SCHEMA`/`CLAIM_SCHEMA`，**不允许增减字段、布尔冒充序列/revision**；域分离 `CES/EC309/ExternalCAS/IndependentStateReadback/v1\0` 及公钥均完全沿用已独立给定的 observer Ed25519 公钥，不接受签名由另一角色/身份/key 替换。
- 所有前任记录都必须绑定同一 verified `registry_id`、原外部 CAS authority id/pub、observer id/pub、namespace、原 EC307 case/evidence raw SHA、原 EC308 receipt raw SHA、其已验签 claim digest/nonce、原裁决 outcome/revision/head。当前窗口**不验证不同历史 CAS 裁决**；不同来源一律拒绝，不擅自跨裁决推断历史。
- 每条签名中的 `readback_sequence` 必须恰好前任 +1；`previous_readback_raw_sha256` 必须等于前条整文件 raw SHA；`previous_readback_observed_revision` 必须等于前条在**已验真签名**中的 observed revision；最终对齐当前独立钉住的外部前任锚。断链、伪造签名、重复 SHA/nonce、错公钥/身份/namespace、非法类型或窗口越界为 **拒绝 `exit 3/4/5`**。
- 对边界所知 revision 与每条历史/当前 observation 逐项判断：**已签 revision 下降**或**连续同 revision 异 head**都保留真实矛盾的签章证据，报告 `exit=2`、候选 `null`；不同 revision 的 head 不比较相等性，避免将合法 version 更新视为冲突。非创世边界**没有 head pin**，不可能对其检测“同版本异头”，这项限制必须由外部历史保管解决。
- 没有回退/同版本异头，并且**最新 EC309** 与已验真的 EC308 committed claim 同 revision/head 相容，才能返回 `exit=0`（仅“连续签名窗口与当前裁决声明相容”）。若最新 EC309 自身较新/较旧/同 rev 冲突或原 EC308 是前置失败，即使历史签章全部合法也返回 `exit=2` 且没有赢家。绝不写外部 CAS/原业务记录。

| 新 `status` | 退出码 | 结论 |
|---|---:|---|
| `bounded_signed_history_contiguous_and_current_claims_compatible_not_store_proof` | `0` | 窗口全部已签历史连续且无相邻观察回退/异头；最新双签 committed 声明相容；非真实 CAS 存储证明 |
| `signed_history_observer_revision_rollback_detected` | `2` | 其中一条**有真签**观察相对于前条已知 revision 倒退；无赢家 |
| `signed_history_same_revision_conflicting_heads_detected` | `2` | 两条连续真签观察在相同 revision 声称不同 head；无赢家 |
| `bounded_signed_history_valid_current_decision_not_corroborated` | `2` | 历史链接和连续性验真，但最新裁决/观察尚未相容或原裁决失败；无赢家 |

跨窗口源文件/完整 SHA/签名/链接拒绝属于 `permission_denied = 3`；非法输入 `invalid_input = 4`；本机无法读签名素材 `unavailable = 5`。签名有效的反常状态与签章/输入非法的硬拒绝**不混淆**，更不会由冲突自动选取 CAS 赢家。

## CLI 使用（只读）

下面 `PLACEHOLDER_*` 必须替换为从**独立可信渠道**取得的参数/路径，程序不会为你生成签名，也不会从包内推定信任。

```bash
python3 scripts/ces_cas_history.py verify \
  --fork-case-file /private/case.json --expected-fork-case-sha256 PLACEHOLDER_CASE_SHA \
  --fork-evidence-file /private/fork-evidence.json --expected-fork-evidence-sha256 PLACEHOLDER_FORK_SHA \
  --receipt-file /private/cas-receipt.json --expected-receipt-sha256 PLACEHOLDER_CAS_RECEIPT_SHA \
  --cas-authority-id independent_cas_site --cas-public-hex PLACEHOLDER_CAS_PUBLIC_HEX \
  --request-nonce-sha256 PLACEHOLDER_ORIGINAL_NONCE_SHA \
  --expected-parent-cas-revision 27 --expected-parent-cas-head-sha256 PLACEHOLDER_PARENT_HEAD_SHA \
  --readback-file /private/readback-3.json --expected-readback-sha256 PLACEHOLDER_LATEST_SHA \
  --cas-store-namespace-id external_registry_namespace \
  --observer-id readback_independent_site --observer-public-hex PLACEHOLDER_OBSERVER_PUBLIC_HEX \
  --readback-request-nonce-sha256 PLACEHOLDER_LATEST_NONCE_SHA \
  --expected-previous-readback-sequence 2 \
  --expected-previous-readback-raw-sha256 PLACEHOLDER_READBACK_2_SHA \
  --expected-previous-readback-observed-revision 28 \
  --boundary-sequence 0 \
  --boundary-raw-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  --boundary-observed-revision none \
  --previous-readback /private/readback-1.json PLACEHOLDER_READBACK_1_SHA PLACEHOLDER_NONCE_1_SHA \
  --previous-readback /private/readback-2.json PLACEHOLDER_READBACK_2_SHA PLACEHOLDER_NONCE_2_SHA \
  --out /private/ec310-audit.json
```

CLI `verify` 只有 `--out` 为可选：保存新的路径无关/无私钥审计快照，0600、O_EXCL、fsync，不覆盖旧文件。如果审计者另行收到报告文件并独立钉住其整文件 SHA，可用**相同全部原始文件与外部 pin** 改为：

```bash
python3 scripts/ces_cas_history.py verify-report [上面 verify 的全部输入、但无 --out] \
  --audit-report-file /private/ec310-audit.json \
  --expected-audit-report-sha256 PLACEHOLDER_AUDIT_RAW_SHA
```

`[上面 ...]` 只是说明文字，不能直接复制作为实际 CLI 参数。`verify-report` 重新验完整 EC294～310 源证据并重建所有字段，不读取旧报表中的真假布尔值作结论。

统一控制台严格只允许：

```bash
python3 scripts/ces_next.py audit-history DeliveryAudit VerifySignedCasHistory \
  [上面 verify 的全部必填参数与有序的 --previous-readback 三元组，但不含 --out]
```

控制台为固定子进程、只读校验、严格 action/mode 限定，不接受签名私钥、更新/审批/commit、任意 Host 代理、CAS URL 或 `--out`，原 Router 74 路/11 HOST_REQUIRED 默认拒绝策略不变。EC309 `audit-readback` 旧入口仍可用，不修改原语义。

## 报告内容与最终现场待验

路径无关报告列明窗口边界、各前驱 `sequence/raw SHA/signed claim SHA/request nonce SHA/observed revision/head`、最新签名记录、异常连续序号、最新 EC309 单独 status，且字段中明确 `history_before_non_genesis_boundary_replayed=false`、`previous_physical_external_cas_reads_verified=false`、`real_cas_commit_or_global_latest_proven=false` 等边界；程序不包含私钥签发或实际网络 CAS 客户端。窗口长度最大 16 条**前驱**加当前一条。

真实多轮外部独立 readback 的组织授权、密钥保管与撤销、独立 nonce 全网唯一及时序、可信统一命名空间/线性化 CAS/WORM 持久存储、窗口之外的前驱原件及任何并行分叉完整搜集、跨裁决/跨 observer 历史、原先全部 ZIP/ACK 物理原件、生产 Provider/Inbox、PowerShell7 原15 Smoke、Windows/macOS、Git/CI/E63–E66、恶意竞态/NFS/断电、用户最终联合验收，都必须留待具备真实环境时确认。EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、global Quality PASS=false、final `NOT_STARTED` 不因本轮单一功能而改变。
