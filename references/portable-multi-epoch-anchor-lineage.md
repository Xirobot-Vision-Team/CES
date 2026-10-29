# EC297 操作手册：多 epoch 完整审计锚点链的离线移机验证

版本：**V6.07 / R297 / EC297**。入口 `scripts/ces_anchor_lineage.py`；只消费原 EC294/EC295/EC296 **已产生**的有签历史。离线验证不代替实际外部保管、审计授权、签名设备隔离或生产 Provider 端到端验收。

## 一、准备证据

必须具备 **3～16 个按发生顺序排列的 epoch**，每代需：

- 原 EC295 完整 policy（保留原始文件字节，并从可信来源获得**该原始文件** SHA256）；
- 从 `sequence=1 / previous=000...000` 到真实末端、无跳号的**全部**原 EC295 checkpoint 文件，文件顺序即审计顺序；每代一个 SHA256 checkpoint tip（EC295 canonical JSON SHA，**不是** checkpoint 文件原始字节 SHA）。
- 每一对相邻代之间，保留一份已由 old_keeper/old_witness/new_keeper/new_witness 完整签署的 **EC296 bridge**、其 canonical SHA、原 EC296 生成时的 `minimum_fresh_readback_unix`。`record` 必须是 `null`；`readback` 必须是当时由操作员独立记录的最早时刻。

EC297 **不会**读取原私钥/HMAC key/status token，不能替代 EC296 生成 bridge，也不会生成任何新 EC294 状态 Readback。请先在原 EC295 和 EC296 操作流程中另行完成授权、记录、签署和原始可携证据保管。

## 二、编辑本机输入路径文件

仅在当前机器的**私有目录**中建立 JSON，例如 `/secure/ces297/inputs.json`（`/secure` 为示例路径，不会自动创建）：

```json
{
  "schema": "ces.ec297.offline_rotation_lineage_inputs.v1",
  "epochs": [
    {
      "policy_file": "/secure/epoch0/policy.json",
      "policy_sha256": "<64位十六进制原始文件SHA256>",
      "checkpoint_files": ["/secure/epoch0/001.json", "/secure/epoch0/002.json"],
      "checkpoint_tip_sha256": "<64位十六进制canonical末端SHA256>"
    },
    {
      "policy_file": "/secure/epoch1/policy.json",
      "policy_sha256": "<64位十六进制原始文件SHA256>",
      "checkpoint_files": ["/secure/epoch1/001.json"],
      "checkpoint_tip_sha256": "<64位十六进制canonical末端SHA256>"
    },
    {
      "policy_file": "/secure/epoch2/policy.json",
      "policy_sha256": "<64位十六进制原始文件SHA256>",
      "checkpoint_files": ["/secure/epoch2/001.json"],
      "checkpoint_tip_sha256": "<64位十六进制canonical末端SHA256>"
    }
  ],
  "bridges": [
    {
      "bridge_file": "/secure/bridge0-to-1.json",
      "bridge_sha256": "<64位十六进制EC296 bridge canonical SHA256>",
      "minimum_fresh_readback_unix": null
    },
    {
      "bridge_file": "/secure/bridge1-to-2.json",
      "bridge_sha256": "<64位十六进制EC296 bridge canonical SHA256>",
      "minimum_fresh_readback_unix": 1791000000
    }
  ]
}
```

上面的十六进制字段是**占位符**，`1791000000` 只是语法示意，并不是可信的读回时间。实际应用必须使用已取得的真实 SHA 和对应 EC296 轮换审批时记录的时间。所有路径必须是绝对路径；请不要把私钥、状态 Token 或原 HMAC secret 放进输入文件。

## 三、生成可移机 commitment（仅草案）

在已创建的 owner-only 0700 私有目录中，以该轮用户运行：

```bash
python3 -I -B scripts/ces_anchor_lineage.py propose-lineage \
  --inputs-file /secure/ces297/inputs.json \
  --out /secure/ces297/lineage-commitment.json
```

此命令将**真实地完整验证每个历史签回、每代双签与每张四签桥**，然后以 `O_EXCL` / `0600` / 文件和父目录 `fsync` 写入不包含路径的承诺文档。正常结果的状态仅为 `untrusted_offline_lineage_proposal_only`，不会标注“已经异地锚定”。必须让具有独立授权的保管人员，将承诺文件和结果中的 `lineage_commitment_sha256`、**首代 tip**、**最新 tip**、**最新 bridge SHA**（以及最新 epoch 的身份与序号）保存在另行信任的、具备抗回滚能力的外部渠道。保留完整旧世代和每张旧 bridge；不要只存最新签名。

## 四、全历史验证（必须四项外部锚点）

从**独立外部记录**取得上一步的完整 commitment SHA + 首代 tip + 最新 tip + 最新 bridge SHA，并在另一受信任终端执行：

```bash
python3 -I -B scripts/ces_anchor_lineage.py verify-lineage \
  --inputs-file /secure/ces297/inputs.json \
  --commitment-file /secure/ces297/lineage-commitment.json \
  --expected-commitment-sha256 ACTUAL_INDEPENDENT_COMMITMENT_SHA256 \
  --expected-root-tip ACTUAL_INDEPENDENT_ROOT_CHECKPOINT_TIP \
  --expected-latest-tip ACTUAL_INDEPENDENT_LATEST_CHECKPOINT_TIP \
  --expected-latest-bridge-sha256 ACTUAL_INDEPENDENT_LATEST_ROTATION_BRIDGE_SHA256
```

统一控制台提供同义只读验真入口（不能执行 `propose-lineage`、不能签或发）：

```bash
python3 -I -B scripts/ces_next.py audit-lineage DeliveryAudit VerifyLineage \
  --inputs-file /secure/ces297/inputs.json \
  --commitment-file /secure/ces297/lineage-commitment.json \
  --expected-commitment-sha256 ACTUAL_INDEPENDENT_COMMITMENT_SHA256 \
  --expected-root-tip ACTUAL_INDEPENDENT_ROOT_CHECKPOINT_TIP \
  --expected-latest-tip ACTUAL_INDEPENDENT_LATEST_CHECKPOINT_TIP \
  --expected-latest-bridge-sha256 ACTUAL_INDEPENDENT_LATEST_ROTATION_BRIDGE_SHA256
```

四 SHA、每代 policy 文件原 SHA、checkpoint tip 和 bridge SHA 都必须一致；外部历史有更新时须重新生成并**另行可信保存**新的整条 lineage 承诺。不能用本机刚生成的候选 SHA，假装已经独立外部托管，或把一个两代 bridge 的有效性当作三代后继已被认证。

返回码：`0` 为已对**提供的外部 pin**完成离线全链验真，`3` 为权限/证据/锚点拒绝，`4` 为输入格式不合约，`5` 为操作环境不可用。结果中 `actual_independent_off_host_retention_or_unique_fork_proven=false` 永远为 false。

## 五、移机和风险排查

移机后复制**全套**原始 policy/checkpoint/bridge，修改本地 `inputs.json` 路径，保留每个 SHA、epoch/bridge 顺序与最早 readback Unix 值；commitment canonical SHA 必须保持完全相同，不因路径变化而变化。若出现 `EXTERNAL_LINEAGE_COMMITMENT_SHA_MISMATCH`，先从独立渠道核对外部 pin；若出现 `COMMITMENT_NOT_EQUAL_TO_ALL_VERIFIED_EPOCHS_AND_BRIDGES`，说明本机文件组成与外部已锚定的全历史不符；若出现 `HISTORICAL_KEEPER_OR_WITNESS_KEY_REUSED`，说明跨越非相邻代重复使用旧密钥，必须复查轮换政策；若出现 `NEW_EPOCH_MUST_FOLLOW` 或 `INDEPENDENT_FRESH_READBACK_TIME`，请检查 EC296 原 Readback/Record 交接证据，而不是篡改时间戳绕过验证。

**重要能力边界：** 一套合法签名和合法 pinned commitment **不能证明世界上不存在另一条合法分叉**。WORM 或外部日志部署、保管人独立性、钥匙吊销/替换策略、可信 UTC/持久时钟、现场签名设备及跨主机权限，仍需在后续独立施工/用户验收完成。永远不得将历史 `UNKNOWN`、Provider 接受或单机模拟误写为生产收件成功。
