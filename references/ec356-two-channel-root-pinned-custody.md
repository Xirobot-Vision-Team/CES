# EC356 — 两个调用方分别固定 root SHA 的离线 checkpoint / witness 原字节托管确认

## 范围与证明语义

这是 **V6.66/R356 单独新增的一层离线只读验证**，在每次执行时重新跑 EC355→EC354→EC337 实际原签名与原始文件 SHA；**不**消费 EC355 成功 JSON 作信任输入，不为缺失父证明“补办成功”，不写机构文件，也不选择全球最新 head。合法审计状态一律 `exit_code=2`、`*_unresolved`，只意味着在调用方给定文件和密钥内满足有限密码学条件。

对 EC355 `furnished_originals` 真回执，要求**两家声明不同的渠道**各出示独立本地文件路径，并由两个 SHA-pinned 机构 root 各自签署渠道授权、由两把渠道独立 Ed25519 私钥签署原 SHA+长度、旧 EC355 两个不同 requested_role 与 receipt 的绑定。新证据签名链真验，不代表线下身份、合法许可、两台物理机、物理 custody、外部独立公钥出处、可信自报时间或网络上不存在隐藏分叉。root key SHA 必须由调用方**另外**可靠获得，不能从 bundle 中的 root reference 或自称机构名称推导可信身份。

## 命令

```bash
# 历史参数 = 前一版 audit-checkpoint-disclosures 所需全部实物、SHA、UTC 参数
python -I -B scripts/ces_cas_two_channel_custody.py derive-custody-handoff \
    <EC355全部历史参数>

python -I -B scripts/ces_cas_two_channel_custody.py audit-two-channel-custody \
    <EC355全部历史参数> \
    --two-channel-custody-evaluation-utc 2026-10-26T00:10:00Z \
    --custody-bundle-file /evidence/custody-bundle.json \
    --expected-custody-bundle-sha256 <64位小写SHA256> \
    --root-a-public-key-file /pins/organization-a-root.bin \
    --expected-root-a-public-key-sha256 <64位小写SHA256> \
    --root-b-public-key-file /pins/organization-b-root.bin \
    --expected-root-b-public-key-sha256 <64位小写SHA256>

# 同一参数也可走固定隔离统一入口，只允许下面 Action + Mode：
python -B scripts/ces_next.py audit-two-channel-custody \
    DeliveryAudit AuditTwoChannelCustody <上述审计的全部 flags>
```

`--two-channel-custody-evaluation-utc` 是独立字段，绝不复写历史 `custody_evaluation_utc` 或 `checkpoint_disclosure_evaluation_utc`。所有 UTC 仅为 caller/provider **自报值**。旧参数详见 `--help` 与 `references/ec355-signed-checkpoint-disclosure.md`。统一入口以固定 `python -I -B` 子进程隔离，严格核对 JSON 字段/结果码，只允许以上已列只读模式；不授权 `DeliverySend`、签发、文件写入、HTTP、CAS/WORM、Provider。

## 原始文件协议（严格 canonical JSON）

`_read_pinned` 校验全部绝对原件路径、SHA-256、长度上界及重复键/非 canonical JSON；独立新路径不得别名父原件，不允许 symlink 祖先或同 inode 硬链接充当机构文件副本；审计返回前迟到再读 SHA。示例仅演示字段形状，**不能直接当做可信凭证**，所有占位 SHA 和签名应由调用方提供的真实原始字节生成：

```json
{
  "schema": "ces.ec356.pinned_two_channel_custody_bundle.v1",
  "channels": [
    {
      "slot": "a",
      "institution_id": "institution_a",
      "channel_id": "channel_a",
      "claimed_organization": "Example Institution A",
      "root_public_key": {"path": "/pins/a-root.bin", "sha256": "<原始32字节公钥整文件 SHA>"},
      "root_reference": {"path": "/evidence/a-root-reference.json", "sha256": "<SHA>"},
      "channel_public_key": {"path": "/pins/a-channel.bin", "sha256": "<SHA>"},
      "channel_authorization": {"path": "/evidence/a-channel-authorization.json", "sha256": "<SHA>"},
      "acknowledgements": [
        {
          "acknowledgement": {"path": "/evidence/a-ack-1.json", "sha256": "<SHA>"},
          "checkpoint_original": {"path": "/custodian-a/checkpoint-copy.bin", "sha256": "<来自EC355真回执的checkpoint整原SHA>"},
          "witness_original": {"path": "/custodian-a/witness-copy.bin", "sha256": "<来自EC355真回执的witness整原SHA>"}
        }
      ]
    }
  ]
}
```

审计另外需要调用方在 bundle **之外**分别传入 root A 和 B 的 `--root-*-public-key-file`/`--expected-root-*-public-key-sha256`。如只提供 A，本层保留缺 B 的状态，**不会**把一根 key 或一个签收人计为双渠道。

### `root_reference`（由该 root 私钥签名）

```json
{
  "schema":"ces.ec356.self_signed_institution_root_reference.v1",
  "institution_id":"institution_a",
  "claimed_organization":"Example Institution A",
  "root_public_key_original_sha256":"<A公钥原字节SHA>",
  "valid_from_utc":"2026-10-25T00:00:00Z",
  "valid_until_utc":"2026-11-25T00:00:00Z",
  "signature_ed25519_hex":"<root签名的128位小写十六进制>"
}
```

签名消息为 `b'CES/EC356/InstitutionRootReference/v1\x00' + canonical(body)`；其中 `\x00` 是字节零，body 不包含 `signature_ed25519_hex`。源 `claimed_organization` **必须被本条自签 root reference 绑定**，防止非签名 manifest 更改组织显示名，但这依然不是独立身份认证。

### `channel_authorization`（由 root 私钥签名）

```json
{
  "schema":"ces.ec356.root_signed_channel_authorization.v1",
  "institution_id":"institution_a",
  "channel_id":"channel_a",
  "root_reference_original_sha256":"<上方 root reference JSON 整原 SHA>",
  "channel_public_key_original_sha256":"<A渠道公钥原字节SHA>",
  "claimed_physical_site_id":"site_a",
  "valid_from_utc":"2026-10-25T00:00:00Z",
  "valid_until_utc":"2026-11-20T00:00:00Z",
  "signature_ed25519_hex":"<root签名>"
}
```

签名域 `b'CES/EC356/RootChannelAuthorization/v1\x00'`；授权的声明时间区间必须完全包含在机构根自签区间中，且审计评估时间和每条 ack 自报时间在二者有效期内。`claimed_physical_site_id` **只是自称地点**，不自动证明不同城市或机房。

### `acknowledgement`（由 channel 私钥签名）

```json
{
  "schema":"ces.ec356.channel_signed_original_custody_acknowledgement.v1",
  "acknowledgement_id":"ack_1",
  "parent_disclosure_bundle_original_sha256":"<实际 EC355 disclosure bundle 整原 SHA>",
  "gossip_reply_original_sha256":"<EC354 已核验 gossip reply 整原 SHA>",
  "ec355_request_original_sha256":"<EC355 真签 request 整原 SHA>",
  "ec355_receipt_original_sha256":"<EC355 真签、真实出示原件的 receipt 整原 SHA>",
  "ec355_requested_role":"original_responder",
  "log_id":"log_a",
  "checkpoint_original_sha256":"<EC355 已核验 checkpoint 整原 SHA>",
  "witness_original_sha256":"<EC355 已核验 witness 整原 SHA>",
  "checkpoint_length":1234,
  "witness_length":456,
  "custody_status":"custodied_originals",
  "institution_id":"institution_a",
  "channel_id":"channel_a",
  "channel_authorization_original_sha256":"<本渠道真实授权整原 SHA>",
  "previous_ack_original_sha256":"GENESIS",
  "nonce_hex":"00112233445566778899aabbccddeeff",
  "acknowledged_utc":"2026-10-26T00:02:00Z",
  "signature_ed25519_hex":"<channel签名>"
}
```

签名域 `b'CES/EC356/CustodyOriginalAcknowledgement/v1\x00'`，签名 cover 除签名字段以外的**全部字段**。`custodied_originals` 必须同时呈交两个实际上重新打开、精确 SHA/长度吻合的不同新路径文件。`sha_claim_only` / `unavailable_claim` **必须**两份文件指针及长度都为 `null`，并且不能形成 byte custody quorum；这类 ack 仍真实验签并出示，但只代表签名声明。

每一 EC354 claim 的两条有效 byte acknowledgement 应来自两个不同 root+channel、分别关联 EC355 `original_responder` 和 `independent_peer` 两个不同真签 receipt，且 `checkpoint+witness` **两个完整 SHA 都相同**。两个根或渠道不可重用父 auditor/log/witness 角色公钥，root 和 channel 公钥相互不同，`acknowledgement_id` 和 nonce 全局去重；每个 channel/claim 最多 2 条原 SHA 前驱链，**同父双子签**被报告为 fork 而不是任意选一个最新。任何真签不同 witness pair 或身份/自称 site 碰撞、超 7 日自报 ack 时间、真实父签无 append-only 证据，不得升级结果。

## 状态与审计

每个合法输出仍然 `exit_code=2`, 包含 `channel_evidence`、每 claim 逐条签署原件 SHA、fork/equivocation/incompatible-pair/collision/stale 布尔值、实际父 EC355 `parent_ec355_canonical_result_sha256` 与父 `disclosure_bundle` SHA。充分但仍仅局部自证明的结果后缀是：`ec356_two_root_authorized_channels_signed_same_original_bytes_external_provenance_unproven_unresolved`。

另外七类结果分别代表：父签/append-only 未解、无 EC355 已交付原件、缺两根独立 pin 渠道、缺原字节双 ack、签署分叉/自相矛盾、碰撞或陈旧声明、两渠道签署的原字节对/EC355 角色不匹配。路径/SHA/签名/授权错误和超界输入是**拒绝**而不是合法审计状态（`exit 3/4/5` 及严格 denial schema）。

## 开发测试与真实边界

本轮本地测试利用合成独立 Ed25519 真签、真实原 SHA、真实历史 EC355→EC337 验证链，故足以观察本地签名真实性、角色及原字节绑定失败；旧 EC317/318 深层 fixture 仍是 **MOCK**。但测试在单机完成，不提供第三方 root SHA 来源、官方身份、受信 UTC 或真实两地托管证明。原生 PS7、15 Smoke、Windows/macOS/Git/CI/Provider/E63-E66、远端 CAS/WORM、人工最终验收 **未运行**。完整测试计数和已知超时在 `construction/EC356_LOCAL_REPORT.json`；不声称全部通过。
