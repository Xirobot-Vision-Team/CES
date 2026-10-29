# EC353 — 离线第三方透明日志：真 Ed25519 checkpoint/witness + RFC6962 包含及一致性证明

## 使用边界与现实来源

本轮在 **EC352 全部真签原件重放**之上附加一个只读、外部文件逐项 pinned 的**透明日志声明校验器**，不是日志服务器，也不是颁发机构。核心先实际调用 `key_registry.registry.audit(...)`，该调用再真实重放 EC351→EC337。**不接受上轮任何 `PASS`/`UNRESOLVED` JSON 来代替真实原件。** 重新打开 EC352 的 root reference、signed event 原始字节，按真正 RFC6962 SHA256-CT v1 叶哈希 `SHA256(0x00||raw_bytes)` 校验包含路径。只承认明确呈交的两份 32 字节 Ed25519 log/witness 公钥文件；各自用不同域的 canonical 自签引用固定 whole-SHA、声称机构/网址/有效窗。随后验证被 log key 真签的整原 checkpoint（tree_size、merkle root、previous signed checkpoint SHA），以及独立 witness key 对**该 checkpoint 整原 SHA**的另一个真签声明。不同根公钥、不同组织名或两个 HTTPS URL **均不足以证明**现实的跨组织独立性、外部发布、可信 UTC 或真正可被全世界查询的日志。

## 新入口（纯只读）

- 单独：`python -I -B scripts/ces_cas_transparency_witness.py derive-publication-handoff` + 完整 EC352 输入。生成必须被两个日志纳入的 root/event 清单，仍是 exit2。
- 单独：`python -I -B scripts/ces_cas_transparency_witness.py audit-publication-witnesses` + 完整 EC352 输入及 `--publication-evaluation-utc`、`--publication-bundle-file`、`--expected-publication-bundle-sha256`。
- 统一固定入口：`python -B scripts/ces_next.py audit-registry-transparency DeliveryAudit AuditOfflineRegistryTransparencyWitnesses` + 与上一条 audit 完全相同的命名选项；统一入口仅允许此 Action/Mode 组合，以 `python -I -B` 固定隔离子进程调用上述 audit，并检查 JSON 完整 schema、负能力与 exit code。使用 `--help` 查看完整的 EC352 历史必需命名参数；不要把 EC352 原始根/事件省略，或拿历史报告代替原件。

这些命令**不**持有私钥，不会生成 key/签名、写 checkpoint、抓取 HTTPS、访问证书系统根信任仓库或触碰 Provider/CAS/WORM。所有正常解析的结果只会是 `exit_code=2` 且 `status=*unresolved`。签名或 SHA 故障：`permission_denied`（3）；字段/类型/规范格式错误：`invalid_input`（4）；已明确命名的原件无法读取等：`unavailable`（5）。

## ZIP 输入中的 publication bundle

唯一新增的 bundling 参数是一个 **canonical JSON** 的纯证据路径目录，必须对其**整原字节**提供独立 SHA-256；其列名文件本身也分别附 `{"path":"/absolute/no-symlink/file","sha256":"<64 lowercase hex>"}`。不可重复 JSON key、非标准 canonical、NaN、symlink、未 pin、相互别名或冒充父原件路径。文件内容全部由调用人离线提供，目录只是列名文件来源，绝不代表外界提交确认。JSON 外部大致形状如下（字段名须完全一致；值仅是示意，并非有效证据）：

```json
{
  "schema": "ces.ec353.pinned_publication_evidence_bundle.v1",
  "logs": [
    {
      "log_id": "log_a",
      "log_reference": {"path": "/evidence/log-a-ref.json", "sha256": "<whole SHA256>"},
      "log_public_key": {"path": "/evidence/log-a-pub.bin", "sha256": "<whole SHA256>"},
      "witness_reference": {"path": "/evidence/wit-a-ref.json", "sha256": "<whole SHA256>"},
      "witness_public_key": {"path": "/evidence/wit-a-pub.bin", "sha256": "<whole SHA256>"},
      "checkpoints": [
        {"checkpoint": {"path": "/evidence/cp-a1.json", "sha256": "<whole SHA256>"},
         "witness_statement": {"path": "/evidence/wit-a1.json", "sha256": "<whole SHA256>"},
         "consistency_proof": null},
        {"checkpoint": {"path": "/evidence/cp-a2.json", "sha256": "<whole SHA256>"},
         "witness_statement": {"path": "/evidence/wit-a2.json", "sha256": "<whole SHA256>"},
         "consistency_proof": {"path": "/evidence/cons-a2.json", "sha256": "<whole SHA256>"}}
      ],
      "inclusions": [
        {"path": "/evidence/leaf-a1.json", "sha256": "<whole SHA256>"}
      ]
    }
  ]
}
```

`logs` 必须 0–2 个、按 `log_id` 严格升序且唯一；每条日志的 checkpoint ≤4，inclusions ≤12，tree_size 1..64。提交 0 或 1 路不会错误返回成功，只会产生缺证据的 `unresolved`。两个日志需要分别整原 pin：log key/witness key、两份自签引用、每份 signed checkpoint、见证声明、包含证明、每个非 genesis 递增 checkpoint 的 consistency proof（如果缺失、无效则不得声称 append-only）。日志 key、witness key、EC352 registry root/operator、EC351 source attester 的**同值 key SHA**跨角色禁复用；相同机构声明名称也会显式降级，却不能用不同名称反过来声称真实独立。

### 各真签原件的全部字段

所有 Ed25519 签名对 `domain || canonical(body_without_signature)` 的原始字节签名；签名字段固定为 128 个小写 hex 字符。canonical JSON 由 `offline_transfer_registry.registry.canonical` 定义（sorted keys，无多余空格，UTF-8 bytes）。域分离如下：

- log reference 签名域：`CES/EC353/LogReference/v1\0`；字段 `schema`, `log_id`, `log_public_key_original_sha256`, `claimed_log_organization`, `claimed_log_publication_uri`, `valid_from_utc`, `valid_until_utc`, `signature_ed25519_hex`。`schema=ces.ec353.self_signed_transparency_log_reference.v1`。
- witness reference 签名域：`CES/EC353/WitnessReference/v1\0`；字段 `schema`, `log_id`, `witness_public_key_original_sha256`, `claimed_witness_organization`, `claimed_witness_document_uri`, `valid_from_utc`, `valid_until_utc`, `signature_ed25519_hex`。`schema=ces.ec353.self_signed_checkpoint_witness_reference.v1`。
- checkpoint 真签域：`CES/EC353/LogCheckpoint/v1\0`；字段 `schema`, `log_id`, `log_reference_original_sha256`, `previous_checkpoint_original_sha256`（genesis 字面值 `GENESIS`）, `tree_size`（真正 JSON int）, `root_hash_sha256`（RFC6962 tree hash）, `issued_utc`, `log_signature_ed25519_hex`。`schema=ces.ec353.signed_merkle_checkpoint.v1`。
- witness 真签域：`CES/EC353/CheckpointWitness/v1\0`；字段 `schema`, `log_id`, `checkpoint_original_sha256`, `witness_reference_original_sha256`, `tree_size`, `root_hash_sha256`, `witnessed_utc`, `witness_signature_ed25519_hex`。`schema=ces.ec353.signed_checkpoint_witness.v1`。必须真正重新计算 checkpoint 整原 SHA，并且见证的 size/root 与该 log 真签一致。

非签名但**分别整原 pinned**且实际计算密码学证明的文件：

- `ces.ec353.rfc6962_consistency_proof.v1`：`schema`, `log_id`, `previous_checkpoint_original_sha256`, `next_checkpoint_original_sha256`, `previous_tree_size`, `next_tree_size`, `audit_path_sha256_hex`（≤64 个严格 32 字节 hex）。验证旧树是新树的 RFC6962 **完整前缀**，不能只对比两个根散列字符串。
- `ces.ec353.rfc6962_inclusion_proof.v1`：`schema`, `log_id`, `checkpoint_original_sha256`, `artifact_kind`（`registry_root_reference|registry_event`）, `artifact_original_sha256`, `leaf_index`（JSON int），`audit_path_sha256_hex`。真实按原件字节 `leaf=SHA256(00||raw)`、`internal=SHA256(01||left||right)` 递推，包含路径与 **已真签且已见证** 的整原 checkpoint 的 size/root 比对；多余或不足路径、越界 index、替代原件 SHA 都失败。

## 可报告、不可拔高的结论

- 两路全部实签 + Merkle 校验正常时，仍只可称“**所给四把自签公钥之间相互区别，所给 checkpoint 及见证签名自洽，所给 EC352 逐原件的 RFC6962 包含/一致性在这些特定视图中计算成立**”，其最佳 outcome 是 `ec353_matching_signed_merkle_inclusion_external_publication_unproven` / exit2。
- 一个日志缺件、某项 EC352 root/event 未见、witness 没给、已签同父分叉/同 size 不同 root、旧新 size 回退、错误/缺失一致性链、7 天 witness/检查点声称时间断档、声称同一组织或其签署时序矛盾，均不自动选取最新胜者或补足历史；实际伪签/伪 pin/假包含证明必须拒绝，不能通过另一路真签遮蔽。
- 若 EC352/EC351 的 root 授权、signed source、OCSP/CRL、EC337 ancestry 或历史 fork 未证明，则 EC353 即使真双日志可验证，也**不提升**父结论。
- **依然完全 NOT_PROVEN：** 自签 log/witness 公钥在真实世界的来源认证、第三方实际收存/持续在线发布、签名人的法律/物理独立、外部可发现的全局日志分叉与全历史、真实独立 UTC、合法 TSA、真实 OCSP/CRL/nonce 交互、EC317/318 production custody、远端 CAS/WORM/Provider、PS7/15 Smoke、跨 OS/Git/CI 和最终人工验收。

专门的真实本机自合成密码学测试在 `construction/transparency/test_transparency.py`；**全部机构身份和签名密钥由一个测试进程本地生成**，绝不是官方来源或真实第三方公告。
