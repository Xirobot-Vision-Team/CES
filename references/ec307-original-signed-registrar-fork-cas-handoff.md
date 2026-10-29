# EC307 — 具有相同已钉住父索引的两份真正签名后继：取证、封存和外部 CAS 交接

版本：**V6.17 / R307 / EC307**。这是**本地离线审计工具**，不是独立的 CAS 服务器、签名裁决机关或密钥撤销服务。新 CLI 不接收私钥，统一控制台不允许输出报告或写任何业务状态。

## 可以识别的冲突

将原 EC306 *已分别独立保存整个原始文件 SHA* 的一份父索引和两份候选索引提供给新工具。候选必须都指向 `previous_chain_raw_sha256 = 父索引完整 raw SHA`，且是对父索引**恰好一次**合法动作：

1. **登记候选 `signed_registrar_append`**：保留所有原 epoch 内容和 active epoch 非 tip 字段，当前 epoch 的**原 EC304 登记账本恰好增加一个记录**。重新验完整各代 EC304 Ed25519/账本 SHA/登记连续性，所有原 EC305 签署证书、公钥角色隔离、全部 epoch challenge/ACK 唯一性；新记录必须真正通过原 EC304 `verify` → EC303/302/301…294 最新 ZIP/ACK 的真实签名、证据证明及 SHA 钉住检验。
2. **换钥候选 `governance_signed_epoch_rotation`**：完整冻结所有已有 epoch，严格只追加一个**空的**新 epoch；从独立钉住的旧 ledger SHA/seq 重新核验完整原 EC305 planned 三签或 emergency_compromised 两签证书。不得凭新空 epoch 冒充其已签有一个最新 ACK，不要求提交虚假的新 ACK 参数。

两份候选可以是“登记/登记”“换钥/换钥”或“登记/换钥”。两者的**签名后继**必须真实不同；仅文件名变化、不同原字节 SHA、未钉住来源、不同父节点或仅有未签的索引差异都不能视为已证实的签名竞争。证据对象明确标记：`two_different_originally_signed_same_parent_successors_observed`，CLI `exit_code=2` 表示**观察到需要人工处理的有效冲突**，不是程序崩溃，也不是已选择了赢家。

EC307 的信任锚仍然**必须从工程以外独立记录**，不能把本地命令刚算出的候选 SHA、未经外部确认的 case 文件，直接当成全网或不可回滚的 latest。EC306 索引本身**没有签名**，只有其中所指原 EC304/305 实际签章；EC307 不会声称索引经人签收、身份真实或来源已被不可变独立保存。

## 操作：保留一个只在本机使用的私有 case manifest

创建绝对路径、owner 0700 私有目录中的 `case.json`，普通、单硬链接、owner 0600 文件。它是**工作台定位清单**，路径不可移机但输出证据可以移机后用新 case 全量重算。所有 JSON 必须以规范编码 `sort_keys=True, ensure_ascii=True, separators=(',',':')` 序列化，并有一个尾随 `\n`；不允许重复字段或 casefold 字段碰撞。case raw SHA 需经独立渠道记录、逐次调用都从包外传入。

模板如下；所有尖括号值须替换为真实的绝对路径、64 位十六进制 SHA、完整 EC306 外部 pin，不能直接将模板作为实际授权数据使用：

```json
{
  "schema": "ces.ec307.local_case_manifest.v1",
  "parent": {
    "chain_file": "/private/source-parent-index.json",
    "external": {
      "registry_id": "registry_example",
      "governor_public_hex": "<64-hex-governor-public>",
      "initial_registrar_public_hex": "<64-hex-original-registrar-public>",
      "chain_raw_sha256": "<64-hex-entire-parent-index-raw>",
      "epoch_count": 3,
      "active_registrar_public_hex": "<64-hex-parent-active-registrar-public>",
      "active_ledger_raw_sha256": "<64-hex-parent-active-ledger-or-0000..-if-empty>",
      "active_ledger_sequence": 0
    },
    "ledger_files": ["/private/epoch0-ledger.json", "/private/epoch1-ledger.json"],
    "certificate_files": ["/private/epoch0-to-1-certificate.json", "/private/epoch1-to-2-certificate.json"]
  },
  "candidate_a": {
    "chain_file": "/private/candidate-a-index.json",
    "expected_chain_raw_sha256": "<64-hex-entire-candidate-a-index-raw>",
    "ledger_files": ["/private/epoch0-ledger.json", "/private/epoch1-ledger.json", "/private/candidate-a-ledger.json"],
    "certificate_files": ["/private/epoch0-to-1-certificate.json", "/private/epoch1-to-2-certificate.json"],
    "ack_proof": {
      "bundle_file": "/private/candidate-a-bundle.zip",
      "expected_bundle_sha256": "<64-hex-original-zip-raw>",
      "acknowledgement_file": "/private/candidate-a-ack.json",
      "expected_acknowledgement_sha256": "<64-hex-ack-raw>",
      "sender_id": "source_one", "receiver_id": "receiver_two",
      "receiver_public_hex": "<64-hex-receiver-public>",
      "challenge_sha256": "<64-hex-independent-challenge>",
      "pins": {
        "a_id": "witness_one", "a_public_hex": "<64-hex-a-public>",
        "a_tip": "<64-hex-a-tip>",
        "b_id": "witness_two", "b_public_hex": "<64-hex-b-public>",
        "b_tip": "<64-hex-b-tip>",
        "session_tip": "<64-hex-session-tip>",
        "receipt_tip": "<64-hex-receipt-tip>"
      }
    }
  },
  "candidate_b": {
    "chain_file": "/private/candidate-b-index.json",
    "expected_chain_raw_sha256": "<64-hex-entire-candidate-b-index-raw>",
    "ledger_files": ["/private/epoch0-ledger.json", "/private/epoch1-ledger.json", "/private/candidate-b-ledger.json"],
    "certificate_files": ["/private/epoch0-to-1-certificate.json", "/private/epoch1-to-2-certificate.json"],
    "ack_proof": {
      "bundle_file": "/private/candidate-b-bundle.zip",
      "expected_bundle_sha256": "<64-hex-original-zip-raw>",
      "acknowledgement_file": "/private/candidate-b-ack.json",
      "expected_acknowledgement_sha256": "<64-hex-ack-raw>",
      "sender_id": "source_one", "receiver_id": "receiver_two",
      "receiver_public_hex": "<64-hex-receiver-public>",
      "challenge_sha256": "<64-hex-independent-challenge-b>",
      "pins": {
        "a_id": "witness_one", "a_public_hex": "<64-hex-a-public>",
        "a_tip": "<64-hex-a-tip>",
        "b_id": "witness_two", "b_public_hex": "<64-hex-b-public>",
        "b_tip": "<64-hex-b-tip>",
        "session_tip": "<64-hex-session-tip>",
        "receipt_tip": "<64-hex-receipt-tip>"
      }
    }
  }
}
```

注意：模板的父 active `sequence=0` 表示第三代当前没有 ledger，`active_ledger_raw_sha256` 应是**真正原 EC304 GENESIS SHA，即 64 个 0**，故 parent 的 `ledger_files` 只列出**非空** epoch，而不是每代都填。各候选如果是原 EC305 换钥，应使用 `ack_proof: null`、对应候选空末代 ledger 不应列在 `ledger_files` 中、`certificate_files` **多一份**证书。全部文件按 epoch 发生顺序列表，切勿拿模版 SHA 充作真实信任值。

```bash
# 私有 case 文件由可信操作员生成后，先在独立台账保存 case.json 的完整 raw SHA。
python3 scripts/ces_registrar_forks.py compare \
  --case-file /private/case.json \
  --expected-case-raw-sha256 <INDEPENDENT_CASE_RAW_SHA> \
  --out /private/fork-evidence.json

# 输出 exit=2 表示发现经真签重验的竞争；保存输出的 evidence_report_raw_sha256。
# 另一独立校验端必须准备该设备的 case.json + 全套证据、从独立来源取得各 SHA：
python3 scripts/ces_registrar_forks.py verify-report \
  --case-file /private/case.json \
  --expected-case-raw-sha256 <INDEPENDENT_CASE_RAW_SHA> \
  --evidence-file /private/fork-evidence.json \
  --expected-evidence-report-sha256 <INDEPENDENT_EVIDENCE_RAW_SHA>

# 统一控制台：严格只读、绝无 --out 或私钥/投票/commit 参数；exit=2 表示冲突。
python3 scripts/ces_next.py audit-forks DeliveryAudit CompareRegistrarForks \
  --case-file /private/case.json \
  --expected-case-raw-sha256 <INDEPENDENT_CASE_RAW_SHA>
```

`compare --out` 创建从未存在的新单链接普通文件，0600 / O_EXCL / 文件及父目录 fsync；若没有 `--out` 则仅打印摘要。报告是规范、路径无关 JSON + `\n`，SHA 精确对应**完整原字节**；候选按索引完整 SHA 排序，交换 A/B 顺序不会变化。`verify-report` 不凭报表自己声称的通过字段信任它，须提供独立报表 SHA，再全量重验两个候选的原签名及最新 ACK、逐字段重算出**完全相同**的报告，不做任何输出写入。全部业务证据本身不随报告携带，另一台设备仍须获得原 ZIP/ACK、ledgers 和 certificates。

## 交给独立 CAS/WORM 裁决系统的手册协议（EC307 不执行）

1. 外部权威先单独确认 `external_cas_handoff.expected_parent_chain_raw_sha256` 对应**其不可回滚且仍为最新的**索引。若最新值不是该 SHA，**中止**而非把竞争写成已解决；外部必须审查并保留两条分支，不能重放旧 parent 作掩护。
2. 审查两份有真签的候选记录或治理证书，确认真实授权、人员和密钥托管、签发顺序、已发给外界的 ACK/challenge 是否需要停用；这些不是 SHA 或 Ed25519 本地验签能够决定的事实。`cross_branch_reused_*` 只说明这两份**观察到的**分支之间的关联，不是全网消费唯一性。不得自动把败方挑战重新投入可用池。
3. 由受授权的真正线性化 CAS（或具等效原子条件写入的不可变注册系统）执行：`if latest == expected_parent: latest := ONE independently approved candidate SHA; else abort`。CAS 必须跨并发操作全局原子；本机写两个 `O_EXCL` 文件**不等于 CAS**。
4. 独立归档实际 CAS 结果（权威签名/审计序号、精确父 SHA、候选 SHA、证据报告 SHA、操作者与治理决议、可信时间、成功/拒绝、相关撤销与候选隔离），把**完整结果 SHA** 按独立方式公布。EC307 故意把 `externally_authorized_selection_sha256` / `external_atomic_compare_exchange_receipt_sha256` 保持为 `null`，绝不伪造签名回执或提议自动选胜者。
5. 如需系统自动核验外部 CAS 的**独立真实签章和不可回滚状态**，应在下一独立 EC 中先明确信任根、权威、签名协议及拒绝策略；EC307 没有授予这项业务写权限。

## 状态与实测界限

- 本轮聚焦 9 项在 Linux 本机正常结束，真实复用前轮 EC306/305/304/303/302/301→294 已签的本地 Unix Host/HMAC/fsync fixture，包括两份真正合法的登记分叉、签名换钥与登记竞争、原 ACK 全链验证、后重算外层 SHA 的假签名拒绝、原完整证据重验、独立报告、无覆盖、CLI/控制台只读。
- **未完成：** 真实可信独立全网 SHA 锚定、外部治理权限/裁决、实际原子 CAS/WORM/密钥全球撤销、生产 Provider/Inbox、故障/恶意并发/NFS/断电、跨 Windows/macOS、原生 PowerShell7 原 15 Smoke、Git/CI/E63–E66、旧物理 ZIP/ACK 全历史封存、EC249 全功能闭环、EC250 与 B001 及最终联合验收。签名归属只到公开密钥，不是确定人员身份证明。
- 原 Router **74 路由/11 HOST_REQUIRED 默认拒绝**、PowerShell **V4.60/R150**、EC294–306 原业务/签章/Host 模块及证据格式均不修改；只在 `ces_next.py` 新增精确只读命令。
