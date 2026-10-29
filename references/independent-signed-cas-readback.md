# EC309：第二观察者离线 Ed25519 CAS 回读声明协议、操作与边界

## 1. 正式输入与信任来源

这是一种**离线协议**。请不要把本例中的 JSON 理解成“工具真的去读了 CAS”。原 EC308 CAS authority 已签裁决、EC309 observer 再签自己声称的**一次查询响应**；本程序在接收方做严格原签名、跨声明与外部信任 pin 比对；不包含网络客户端、请求发送、CAS 写操作、真实存储原子性/组织授权/WORM/全网最新的测量。即使两份签名一致，两者也有可能都是错误声明、同一控制域、旧快照或同源伪读。

需要持有原 EC307 **完整 case 文件**、fork evidence 文件、原 EC308 **完整 CAS 已签回执文件**，以及外部 observer 提供的**完整 readback 已签 JSON**。这四份文件各自的**整文件 raw SHA** 必须从独立可信渠道获得，而不能直接从收到的内容计算出来后称为独立信任源。输入必须是绝对路径，父目录 owner-private 0700，文件 owner-private 0600 普通文件、单硬链接、无 symlink，规范 JSON 字节 + LF。

原 EC308 authority 的五个外部输入仍保持：`cas_authority_id`、`cas_authority_public_hex`、`expected_request_nonce_sha256`、`expected_parent_cas_revision`、`expected_parent_cas_head_sha256`。本轮另外要求调用者**包外独立指定**：

| 字段（代码 `observer_trust`） | 含义 |
|---|---|
| `cas_store_namespace_id` | 独立给定的目标 CAS namespace 名称，限 2～32 个安全小写标识字符；仅为声明域绑定，不能自行证明真实存储同一性 |
| `observer_id` / `observer_public_hex` | 第二机关 ID 与独立 Ed25519 公钥，不得复用 CAS 机关或所提供原多代已知签名者公钥 |
| `expected_readback_request_nonce_sha256` | 第二次请求 nonce SHA，与原 EC308 CAS 请求 nonce 必须不同；全局唯一性需外部控制 |
| `expected_previous_readback_sequence` | 包外钉住的前次观察 seq，首次为 `0` |
| `expected_previous_readback_raw_sha256` | 前次**完整 readback JSON 原字节** SHA；首次 64 个 `0` (`GENESIS`) |
| `expected_previous_readback_observed_revision` | 前次声称观察的 CAS revision；首次为 JSON `null`，CLI 传 `none`；以后为 0～`2**63-2` 的十进制整数 |

非首次 `(sequence, SHA, revision)` **必须由历史保管人独立提交**。本轮不携带或重验上一条已签观察原件；只能验证“这份新签名中引用的前驱内容等于单独钉住的前驱锚”，不证明此前历史没有分叉、修改或真实物理查询。

## 2. 回读 JSON v1（精确字段）

外层只有三个字段：

```json
{
  "schema": "ces.ec309.external_signed_cas_readback.v1",
  "claim": {},
  "observer_signature_ed25519": "<128 lowercase hex characters>"
}
```

内层 `claim` 精确具有 **21 项字段**，不能缺少或新增：

| 字段 | 含义 |
|---|---|
| `schema` | `ces.ec309.external_cas_readback_claim.v1` |
| `registry_id` | 原 EC307 完整验真报告 registry ID |
| `cas_authority_id` | 由外部独立指定且与原 EC308 已验签机关一致 |
| `cas_authority_public_hex` | 原 CAS 机关独立钉住的公钥 |
| `cas_store_namespace_id` | 新外部独立指定的 namespace 标识 |
| `observer_id` | 新独立观察者 ID |
| `observer_public_hex` | 新独立观察者 Ed25519 公钥 |
| `ec307_fork_case_raw_sha256` | 原 EC307 case **整文件 SHA** |
| `ec307_fork_evidence_raw_sha256` | 原 EC307 fork evidence **整文件 SHA** |
| `ec308_cas_receipt_raw_sha256` | 原 EC308 authority signed receipt **整文件 SHA** |
| `ec308_cas_claim_raw_sha256` | 经真实复验原 EC308 claim 的 `SHA256(canonical_json(claim))` |
| `original_cas_request_nonce_sha256` | 原 EC308 authority 请求 nonce SHA |
| `readback_request_nonce_sha256` | 第二次观察请求 nonce SHA，需与前者不同 |
| `decision_signed_outcome` | 经原 EC308 密码学重验的裁决类型 |
| `decision_claimed_revision` | 原 EC308 claim 的 observed CAS revision |
| `decision_claimed_head_raw_sha256` | 原 EC308 claim 的 observed CAS head SHA |
| `readback_sequence` | `expected_previous_readback_sequence + 1` |
| `previous_readback_raw_sha256` | 外部钉住的上一条完整 readback SHA 或首次 `GENESIS` |
| `previous_readback_observed_revision` | 外部钉住上一条观察声称的 revision；首次 `null` |
| `observed_cas_revision` | 本次 observer **声称观察**到的 CAS revision |
| `observed_head_chain_raw_sha256` | 本次 observer **声称观察**到的 CAS head 完整原字节 SHA |

签名的**精确消息**：

```python
DOMAIN = b"CES/EC309/ExternalCAS/IndependentStateReadback/v1\0"
message = DOMAIN + json.dumps(claim, sort_keys=True, ensure_ascii=True,
                             separators=(',', ':'), allow_nan=False).encode('ascii')
# 在独立外部观察机关上：signature = observer_private_ed25519.sign(message)
# 本工程只验签；不附带或读取私钥。
```

外层：将小写 hex 128 字符签名放到 `observer_signature_ed25519`，JSON 仍用 `sort_keys=True/ensure_ascii=True/separators=(',', ':')`，最后**加一个 LF (`b'\n'`)**。必须在外部信任介质中另外保存整个外层文件的 SHA256，而非让 JSON 自证有效。任何拼写、字段、顺序、nonce、原消息、签名、raw SHA 不符都拒绝。

## 3. 返回状态含义（都不是实际存储操作证明）

| 实际重验后的关系 | `status` | `exit_code` |
|---|---|---|
| 两签声称的 CAS revision/head 完全相同且原 CAS 机关签**成功裁决声明** | `two_signed_claims_same_revision_head_compatible_not_store_proof` | `0` |
| 同 revision/head，但原 CAS 机关签的是**前置失败声明** | 同上，不认赢家 | `2` |
| 同 revision、不同 head | `two_signed_claims_same_revision_conflicting_heads` | `2` |
| 回读 revision 比原裁决声称更大 | `signed_readback_claims_later_revision_intervening_history_unknown` | `2` |
| 回读 revision 比原裁决声称更小 | `signed_readback_claims_earlier_revision_staleness_or_rollback_unknown` | `2` |
| 回读 revision 小于独立钉住的前次 observer revision | `signed_readback_revision_regresses_below_external_observer_anchor` | `2` |

版本比较不是时间证明：查询 nonce 不证明查询已经真的发生，签名不证明数据来自真实存储；revision 越大不说明其中有原成功裁决，head 匹配也不能回填缺失的版本历史。报告只有在原成功裁决**同版本同 head 相容**时附上原“被两份签名声明共同指向的候选 SHA”；绝不自动写 CAS/选取全球赢家。`3`：安全/独立 pin/签名拒绝；`4`：非法结构/参数；`5`：本地不可用。

## 4. CLI 及统一只读控制台

先由两个组织外部真实签发并**另行通过独立渠道**钉住各数据和 SHA，然后在 `ces` 工程根目录执行：

```bash
python3 scripts/ces_cas_readback.py verify \
  --fork-case-file /private/fork-case.json \
  --expected-fork-case-sha256 FORK_CASE_WHOLE_RAW_SHA \
  --fork-evidence-file /private/fork-evidence.json \
  --expected-fork-evidence-sha256 FORK_EVIDENCE_WHOLE_RAW_SHA \
  --receipt-file /private/issuer-cas-receipt.json \
  --expected-receipt-sha256 ISSUER_RECEIPT_WHOLE_RAW_SHA \
  --cas-authority-id independent_cas_site \
  --cas-public-hex TRUSTED_ISSUER_ED25519_PUBLIC_HEX \
  --request-nonce-sha256 ORIGINAL_CAS_REQUEST_NONCE_SHA \
  --expected-parent-cas-revision 27 \
  --expected-parent-cas-head-sha256 INDEPENDENT_PARENT_EC306_INDEX_RAW_SHA \
  --readback-file /private/observer-readback.json \
  --expected-readback-sha256 OBSERVER_READBACK_WHOLE_RAW_SHA \
  --cas-store-namespace-id external_registry_namespace \
  --observer-id readback_independent_site \
  --observer-public-hex TRUSTED_SECOND_ED25519_PUBLIC_HEX \
  --readback-request-nonce-sha256 SECOND_REQUEST_NONCE_SHA \
  --expected-previous-readback-sequence 0 \
  --expected-previous-readback-raw-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  --expected-previous-readback-observed-revision none \
  --out /private/cas-readback-audit.json
```

只有独立 CLI 的 `verify` 允许可选 `--out`，生成**不覆盖**的 0600、fsync、可移机规范审计。第二名核验者把子命令改为 `verify-report`，删除 `--out`，传 `--audit-report-file /private/cas-readback-audit.json` 与**独立钉住的整文件** `--expected-audit-report-sha256 AUDIT_WHOLE_RAW_SHA`；必须重复提供上面所有原始输入与信任锚，重新执行所有 EC294～309 原签名核验、逐字段重建报表，不信任保存的结果。

统一控制台只读命令：

```bash
python3 scripts/ces_next.py audit-readback DeliveryAudit VerifySignedCasReadback \
  [以上 verify 的全部必填 --字段；删除 --out]
```

方括号是操作说明，**不是可直接传给程序的文本参数**。控制台只允许严格这个 action/mode，不接受 `--out`、私钥、外部 CAS socket/URL、read/write/commit/approve 等参数，也不签字、不写原始业务存储；原 Router 74/11 和原 PowerShell V4.60/R150 不改变。

## 5. 生产联合验证累计清单

需要真实 CAS/WORM 独立 linearizable readback、同 namespace 的实际认证与多角色密钥授权/撤销、全球唯一查询 nonce 与可信时序/不可回退观察历史、外部签发机关实际组织治理、真实两站点并发/网络/NFS/断电、全部旧 ZIP/ACK 原件持久保存、Windows/macOS、原始 PowerShell7 Smoke15、真实 Provider/Inbox、Git/CI/E63–E66、用户最终验收。新增 EC309 **不改变**旧 EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、global Quality PASS=false、final `NOT_STARTED`。
