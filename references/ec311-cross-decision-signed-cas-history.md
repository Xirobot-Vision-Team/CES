# EC311 操作协议：跨不同 CAS 裁决的全源签名观察连续性（严格离线）

## 1. 功能与诚实边界

EC310 只允许多次 EC309 回读声明指向**同一份** EC308 签名裁决。EC311 新增独立交付的 `ec311_cas_decision_history`，允许 **2～8 份按观察序号升序排序的不同已签 EC308 裁决**，每份都必须提供自己独立钉住的 EC307 case、EC307 完整分叉证据、EC308 外部 CAS 机关已签回执、EC309 第二观察者已签回读原件以及对应 SHA、发行 nonce/前置 revision+head、回读 nonce。对每份**分别完整重跑原 EC309→EC308→EC307→EC306→…→EC294**，包括底层原始签名/完整 SHA 验证，绝不把上轮 JSON 审计报告的成功标志当作签名。

每次读取采用原 EC306 owner-private 文件读取：父目录 0700、原件 0600、单硬链接、无符号链接、规范 JSON+LF、完整原字节 SHA pin、inode 稳定检查；从包外取得且由操作员 independently SHA-pinned 的**完整私有 manifest** 提供每份独立原件 raw SHA/nonce/父 CAS 条件。manifest 的 SHA 由**另一个可信渠道事先提供**，不能从 manifest 内容自我生成信任。

同一个窗口须固定 CAS authority ID、公钥、CAS namespace、第二 observer ID、公钥和 registry ID；每份 readback 对应不同的真实 Ed25519 回执，observer 签字/nonce 都独立；CAS 与 observer 的所有请求 nonce 在窗口内不能重复。EC309 原已实现 signer 与本轮原案已知 registrar/receiver/见证签名角色不复用。EC311 禁止重复 signed receipt/claim 或 observer 原件并保留所有原定签名角色隔离。

EC311 **并未实现**真正的在线 CAS/WORM 或存储读取；验证的 `exit=0` 只代表操作员给定窗口内**签名声明相容**，不是 CAS 操作已经发生，也不能证明两个签名机关由不同真人/组织保管、真正拥有该 namespace 读写授权、可信时间和 nonce 全球唯一、没有外部竞争分支、全局最新/不可回滚，也不建立第一个父 CAS 状态的事实证明。

## 2. 输入清单及独立信任来源

manifest 必须是 owner-private `0600`、规范 JSON+单行 `LF`，父目录 owner-private `0700`；规范示例（实际值都需要由相应**包外**提供的 SHA/公钥/nonce 替换）：

```json
{
  "schema": "ces.ec311.cross_decision_signed_history_manifest.v1",
  "cas_authority_id": "independent_cas_site",
  "cas_authority_public_hex": "<64 lower-case hex, independently trusted CAS public key>",
  "cas_store_namespace_id": "external_registry_namespace",
  "observer_id": "readback_independent_site",
  "observer_public_hex": "<64 lower-case hex, separately trusted observer public key>",
  "boundary": {
    "sequence": 0,
    "raw_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "observed_revision": null,
    "observed_head_raw_sha256": null
  },
  "decisions": [
    {
      "fork_case_file": "/private/round1-ec307-case.json",
      "expected_fork_case_sha256": "<full raw SHA>",
      "fork_evidence_file": "/private/round1-ec307-fork-evidence.json",
      "expected_fork_evidence_sha256": "<full raw SHA>",
      "receipt_file": "/private/round1-ec308-receipt.json",
      "expected_receipt_sha256": "<full raw SHA>",
      "expected_request_nonce_sha256": "<issuer nonce SHA>",
      "expected_parent_cas_revision": 27,
      "expected_parent_cas_head_sha256": "<original EC307 signed fork parent SHA>",
      "readback_file": "/private/round1-ec309-readback.json",
      "expected_readback_sha256": "<full raw SHA>",
      "expected_readback_request_nonce_sha256": "<observer query nonce SHA>"
    },
    {
      "fork_case_file": "/private/round2-ec307-case.json",
      "expected_fork_case_sha256": "<full raw SHA>",
      "fork_evidence_file": "/private/round2-ec307-fork-evidence.json",
      "expected_fork_evidence_sha256": "<full raw SHA>",
      "receipt_file": "/private/round2-ec308-receipt.json",
      "expected_receipt_sha256": "<full raw SHA>",
      "expected_request_nonce_sha256": "<new distinct issuer nonce SHA>",
      "expected_parent_cas_revision": 28,
      "expected_parent_cas_head_sha256": "<round1 confirmed signed claim head SHA>",
      "readback_file": "/private/round2-ec309-readback.json",
      "expected_readback_sha256": "<full raw SHA>",
      "expected_readback_request_nonce_sha256": "<new distinct observer nonce SHA>"
    }
  ]
}
```

示例中的 `<...>` 是**占位符**，不是有效输入；实际 JSON 必须是两条至八条规范内容，且每条原件文件使用绝对路径。建议用项目自带原 `ec295_delivery_anchor.operator.store` 的私有规范保存协议写 manifest，现场另一个独立通道记录整份 manifest 的原字节 SHA256，而不是从待审报告、待验原件中寻求信任。

创世 observation 边界必须严格 `(sequence=0, raw_sha256=GENESIS, observed_revision=null, observed_head_raw_sha256=null)`；**这只表示所提供的 observer 记录从 sequence=1 开始**，不能说明原 CAS revision=0 或第一个 CAS parent 是真实存储根。非创世边界要求独立 `(sequence>=1, raw SHA, observed revision, observed head)`；是**尚未重新验真的外部 opaque 锚**。第一份 receipt 的父 `(revision, head)` 必须与非创世边界相同；前史和真实 CAS 状态依然未验。

## 3. 本轮新增真实比较条件

对第 i 条读取其 **真签并独立 pin 的** readback `(sequence, raw SHA, observed revision/head)`，从上一条已经验真的 readback 取得 `expected_previous_readback_sequence/raw_SHA/observed_revision`（仅第一个从外部 boundary 取得），调用原 EC309 进行原件签名+链路比对，并追加检测连续观察 revision 回退 / 同 revision 异 head。

从第二份裁决开始，还必须检查：**第二份 CAS 发行人声称的原子 CAS parent `(revision, head)`** 与上一份已签 CAS decision 的观察结果 `(revision, head)` 完全相同；而上一份已签 observer 声称的 `(revision, head)` 必须和上一份 issuer 声称的相同。**不能**用“新的观察 revision 更大”推断缺失裁决链已存在，不能用回读的自称状态替代上一个发行人的证明。每份已签 committed 裁决本身还必须满足原 EC308 的 parent revision+1 / 原 EC307 两真实候选分支之一。

分级结果及退出码（签名/原字节 SHA/源材料错误走严格 denial，而不是冲突状态）：

| 状态 | 退出码 | 含义 |
|---|---:|---|
| `cross_decision_signed_claim_chain_compatible_not_actual_cas_proof` | 0 | 2～8 个不同真实签章的 committed **声明**，前置条件逐项连续，每份回读两签同版同 head，观察链无矛盾；不证明存储提交 |
| `cross_decision_signed_observer_revision_rollback` | 2 | 窗口内有效签章回读 revision 回退 |
| `cross_decision_same_revision_observer_head_conflict` | 2 | 连续有效签章回读同版异 head |
| `cross_decision_signed_cas_parent_head_or_revision_discontinuous` | 2 | 跨裁决 CAS parent revision/head 不等于上一份已签裁决，或上一 observer 不等于上一 issuer；存在断层 |
| `cross_decision_signed_issuer_or_observer_claim_not_corroborated` | 2 | 曾有签名前置失败、读回旧/新/冲突等，不能选择赢家 |
| `permission_denied` / `invalid_input` / `unavailable` | 3 / 4 / 5 | 文件、签章、schema/角色/独立 pin 校验不通过或环境无法读取；不产生成功声明 |

若多个异常同时存在，优先序为：观察 rollback、同版异 head、父链断层、非 committed/未相容。报告同时保存**所有检测到的异常序号列表**，但任何异常一律不提供赢家。

## 4. 可执行入口

请在用户设备 Unix-like 受控环境，从完整工程根目录执行。**请先确保 `cryptography` 在项目 Python 环境存在，且私有源文件由操作人授权访问。** 下述 `<EXTERNALLY_PINNED_MANIFEST_RAW_SHA>` 必须来自清单外的可信记录：

```bash
python3 scripts/ces_cas_decisions.py verify \
  --manifest-file /private/ec311-manifest.json \
  --expected-manifest-sha256 '<EXTERNALLY_PINNED_MANIFEST_RAW_SHA>'

python3 scripts/ces_cas_decisions.py verify \
  --manifest-file /private/ec311-manifest.json \
  --expected-manifest-sha256 '<EXTERNALLY_PINNED_MANIFEST_RAW_SHA>' \
  --out /private/ec311-audit.json

python3 scripts/ces_cas_decisions.py verify-report \
  --manifest-file /private/ec311-manifest.json \
  --expected-manifest-sha256 '<EXTERNALLY_PINNED_MANIFEST_RAW_SHA>' \
  --audit-report-file /private/ec311-audit.json \
  --expected-audit-report-sha256 '<EXTERNALLY_PINNED_AUDIT_RAW_SHA>'
```

`--out` 仅独立 CLI 的 `verify` 接受；原 EC295 0600/O_EXCL/fsync 不能覆盖旧文件。`verify-report` 必须由另一方独立 pin 整份审计报告 SHA，并**重新运行全部原件的签章与结构验证**，只认 fresh report 字节等于独立签章重放结果。

统一控制台**只读**入口：

```bash
python3 scripts/ces_next.py audit-decisions DeliveryAudit VerifySignedCasDecisionHistory \
  --manifest-file /private/ec311-manifest.json \
  --expected-manifest-sha256 '<EXTERNALLY_PINNED_MANIFEST_RAW_SHA>'
```

不支持 `--out`、私钥、签名、审批、授权升级、网络 CAS 读取/写入/提交、原 Router action/mode 的扩权。输入只通过固定隔离 Python 子进程、严格返回 schema/退出码/否定性证据声明；继续保持原 Router **74 路、11 HOST_REQUIRED 默认拒绝**、原 PowerShell **V4.60/R150** 和原 EC294～310 所有密码学/Host/业务代码不变。

## 5. 实测情况、累积现场验证

本轮 15 个各自独立执行的聚焦场景全部正常通过（测试分批执行以避免当前会话超时）。测试夹具构造两份**不同的原 EC307 同父双分叉**：第一份原 signed s4→s5 commit，第二份以真实 s5 为新父，重新从原 EC303 ACK、EC304 原 registrar 签字追加两条有效候选后由原 EC307 对比；每条再由真正 Ed25519 签出原 EC308 issuer 与 EC309 observer 原件。它们是**本机模拟机构**，不代表生产 CAS 或组织授权。

仍累积：真实双组织/密钥托管及撤销、CAS/WORM 原子性/跨区域副本/回滚与全球 tip、可信时间/nonce/外部最新全历史和所有未提供的竞争分支、历史原 ZIP/ACK 托管、NFS/恶意目录竞争/断电、Windows/macOS、原 PowerShell7 15 Smoke、生产 Provider/Inbox、Git/CI/E63–E66、最终真实业务功能验收。EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、global Quality PASS=false、final `NOT_STARTED` 一律保留。
