# EC296 操作手册：两代 EC295 锚点四签密钥轮换（纯离线）

本工具只读取公钥策略、原 EC294 已签审计证据和 EC295 完整检查点；**不会连接 Provider、执行发送或状态查询，也不会读取原 HMAC 秘钥**。此处所有 SHA 必须由操作者在受信环境**独立保存及传入**。把同一台机器上重新算出的哈希复制给自己，不构成外部防回滚。

## 前提与数据保管

从 CES 工程根目录操作。在受权限保护的私有位置，保留：

- **旧 EC295 policy 原文件与原始文件 SHA256**、旧 epoch 从第一个检查点开始的完整顺序文件，以及**另外保存的最新旧检查点 canonical SHA**。
- 原 EC294 策略原文件与 SHA，以及同一任务/operation/源码 pin。原 EC294 audit 已由真实独立授权业务流程完成；不得以合成状态冒充 Provider/Inbox。
- **新两把 EC295 私钥**分别在独立设备生成，不能重用旧 keeper、旧 witness 或原 EC294 三把签名公钥；新策略用原 EC295 `prepare-policy` 绑定同一原 EC294 策略、Job 和 operation。旧私钥必须保留到交接四签并完成可信外部归档，不要提前删除。

```bash
python3 -I -B scripts/ces_delivery_anchor.py keygen-offline --private-out /private/new-keeper.key
python3 -I -B scripts/ces_delivery_anchor.py keygen-offline --private-out /private/new-witness.key
python3 -I -B scripts/ces_delivery_anchor.py prepare-policy   --original-policy-file /private/ec294-policy.json   --original-policy-sha256 ORIGINAL_EC294_POLICY_RAW_SHA   --operation-id EXISTING_ORIGINAL_OPERATION_SHA   --job-sha256 EXISTING_ORIGINAL_JOB_SHA   --keeper-public-hex NEW_KEEPER_PUBLIC_HEX   --witness-public-hex NEW_WITNESS_PUBLIC_HEX   --out /private/new-ec295-policy.json
```

新策略的 `policy_sha256` 是**policy 文件原始字节 SHA**（输出 JSON 包含末尾换行）；不要将其误当 `sha(canonical_object)`。旧策略保持不变。

## 1. 建立新 epoch 的首张 EC295 检查点

**推荐无远端新查询方案：** 从可信外部时间源记录 `MINIMUM_FRESH_READBACK_UNIX`，在此后**独立批准并执行一次原 EC294 `Readback`**，以旧 epoch 最末端外部固定的审计 HMAC 头作为它的 `expected_head_hmac_sha256`。保留 EC294 `Readback` 原 JSON 响应与原 grant。此流程不涉及原 EC226 status token、不联系 Provider、不修改原 EC227 审计。操作者无权限触发 EC294 时必须停止，不能编造签回。

另可采用真正新增原 EC294 `Record` 的路径，但需**新**的独立原 EC226/EC294 票及原审计事件数推进；EC296 本身绝不会替操作者发起 Record。

用新策略依原 EC295 流程封存该回执，**不提供 `--previous-file`**：新 epoch 的首张检查点自身是 sequence=1，关联旧 epoch 的责任由后面的四方 bridge 承担。

```bash
python3 -I -B scripts/ces_delivery_anchor.py prepare   --policy-file /private/new-ec295-policy.json   --policy-sha256 NEW_EC295_POLICY_RAW_SHA   --response-file /private/new-ec294-response.json   --grant-file /private/new-ec294-grant.json   --out /private/new-ec295-prepared-1.json

# 在两台分别负责签名的设备上，按 EC295 旧手册分别执行
# sign-keeper-offline / sign-witness-offline；
# 然后用 assemble 生成 /private/new-ec295-checkpoint-1.json。
```

若选 `record`，上述 `prepare` 还需要 `--read-grant-file /private/new-ec226-read.json`；不能省略原 Record 所需 Read grant。读取新检查点的 `signed_checkpoint_tip_sha256`，作为后续**待验证的新 tip**。此时还**不能声称新 tip 已被外部托管**。

## 2. 形成精确轮换提案

以下 `OLD_CHECKPOINT_*` 和 `NEW_CHECKPOINT_*` 需从 genesis **按顺序**重复 `--old-checkpoint-file` / `--new-checkpoint-file`，不得只给末条或自行补造缺失记录。每个 epoch 最多 64 条。

```bash
python3 -I -B scripts/ces_anchor_rotate.py prepare   --old-policy-file /private/old-ec295-policy.json   --old-policy-sha256 OLD_EC295_POLICY_RAW_SHA   --old-checkpoint-file /private/old-checkpoint-1.json   --old-checkpoint-file /private/old-checkpoint-2.json   --expected-old-tip EXTERNALLY_RETAINED_OLD_TIP   --new-policy-file /private/new-ec295-policy.json   --new-policy-sha256 NEW_EC295_POLICY_RAW_SHA   --new-checkpoint-file /private/new-checkpoint-1.json   --proposed-new-tip EXPLICIT_NEW_CHECKPOINT_TIP   --minimum-fresh-readback-unix MINIMUM_FRESH_READBACK_UNIX   --out /private/ec296-prepared.json
```

**只有新 epoch 首张是 `readback` 时才提供 `--minimum-fresh-readback-unix`**。若首张是 `record`，必须**删去**这一参数。此时间至少应是操作员独立记录的开始时间且不早于新签回；工具要求新签回时间严格晚于旧最后签回。四张票会把此时间阈值一起签在轮换声明内。

`prepare` 对双方政策原字节 SHA、原 EC294 grant/签回、每个 EC295 签名/父 digest、原审计计数与 HMAC 头重新核验；新 epoch `readback` 模式要求头和条数不变化，`record` 模式要求数量增长和 HMAC 头变化。**两种模式不得互相冒充。**

## 3. 四把旧/新密钥分别线下签字

每个实际签名角色都应在**自己**的隔离环境内拿到同一份已核验的 policy、完整两代 checkpoint 链、受信旧 tip、新候选 tip、`ec296-prepared.json` 和自己的私钥。各次签字**重复上述所有公共参数**；绝不因为已有其他三张票就跳过自己的完整历史检查。

```bash
# 以下示例使用公共参数列表的占位写法；实际 CLI 必须显式提供第2节所有
# --old-policy-file/--old-policy-sha256/--old-checkpoint-file/... 参数。
python3 -I -B scripts/ces_anchor_rotate.py sign-old-keeper-offline   ...PUBLIC_TWO_EPOCH_ARGS...   --prepared-file /private/ec296-prepared.json   --private-key-file /private/old-keeper.key   --out /private/ec296-old-keeper-vote.json
```

用完全相同的公共参数依次或在独立设备上执行：

- `sign-old-witness-offline` 搭配旧 witness 私钥和专属 vote 输出。
- `sign-new-keeper-offline` 搭配新 keeper 私钥和专属 vote 输出。
- `sign-new-witness-offline` 搭配新 witness 私钥和专属 vote 输出。

四张票的 `prepared_sha256` 必须相同，且四个角色名、公钥、Ed25519 验签域各不相同。旧时代签字表示明确同意“释放确切旧 tip 至此新 epoch”，新时代签字表示接受该原审计历史。不同终端同路径不是签署身份隔离的证明。

## 4. 组装、独立保管与验证

`assemble` 需要相同公共参数、`--prepared-file` 和四个 `--old-keeper-vote-file`、`--old-witness-vote-file`、`--new-keeper-vote-file`、`--new-witness-vote-file`；输出 `--out /private/ec296-rotation-bridge.json`。它返回 canonical JSON `rotation_bridge_sha256`。**先通过真实独立渠道**保管旧最新 tip、新最新 tip、轮换 bridge canonical SHA 和完整两条原始历史、政策/bridge 文件，才可将新策略作为运营上的生效版本。

随后执行：

```bash
python3 -I -B scripts/ces_anchor_rotate.py verify-rotation   --old-policy-file /private/old-ec295-policy.json   --old-policy-sha256 OLD_EC295_POLICY_RAW_SHA   --old-checkpoint-file /private/old-checkpoint-1.json   --old-checkpoint-file /private/old-checkpoint-2.json   --expected-old-tip EXTERNALLY_RETAINED_OLD_TIP   --new-policy-file /private/new-ec295-policy.json   --new-policy-sha256 NEW_EC295_POLICY_RAW_SHA   --new-checkpoint-file /private/new-checkpoint-1.json   --proposed-new-tip EXPLICIT_NEW_CHECKPOINT_TIP   --expected-new-tip INDEPENDENTLY_RETAINED_NEW_TIP   --bridge-file /private/ec296-rotation-bridge.json   --expected-rotation-sha256 INDEPENDENTLY_RETAINED_BRIDGE_SHA   --minimum-fresh-readback-unix MINIMUM_FRESH_READBACK_UNIX
```

统一控制台同样可验证，不提供 `--proposed-new-tip`（会使用 `--expected-new-tip`）：

```bash
python3 -I -B scripts/ces_next.py audit-rotate DeliveryAudit VerifyRotation   --old-policy-file /private/old-ec295-policy.json   --old-policy-sha256 OLD_EC295_POLICY_RAW_SHA   --old-checkpoint-file /private/old-checkpoint-1.json   --old-checkpoint-file /private/old-checkpoint-2.json   --expected-old-tip EXTERNALLY_RETAINED_OLD_TIP   --new-policy-file /private/new-ec295-policy.json   --new-policy-sha256 NEW_EC295_POLICY_RAW_SHA   --new-checkpoint-file /private/new-checkpoint-1.json   --expected-new-tip INDEPENDENTLY_RETAINED_NEW_TIP   --bridge-file /private/ec296-rotation-bridge.json   --expected-rotation-sha256 INDEPENDENTLY_RETAINED_BRIDGE_SHA   --minimum-fresh-readback-unix MINIMUM_FRESH_READBACK_UNIX
```

如果采用 `record` 交接，两条验证命令同样须去掉 `--minimum-fresh-readback-unix`。所有 JSON 输出都是**离线历史密码学验证**，不是生产发送/已送达/外部托管成功证明；返回拒绝时禁止自行重置链或跳过缺失证据。保留全部旧 epoch 文件、四票和最终 bridge 用于将来人工审查。

## 未完成的部署边界

EC296 没有真实的异地不可变锚点、独立人员认证、集中吊销名单、多 epoch 任意长度链的全球唯一最新状态、可靠外部 UTC、断电恢复验收或生产 Provider/Inbox 证明。即使四签合法，四把私钥均泄露或外部 pin 可被一同修改，仍不能阻止恶意改写。需要由用户在最后阶段统一完成真实跨人/跨机、PowerShell7、原 15 Smoke、Windows/macOS、E63–E66、外部 Provider/Inbox 与不可回滚保管验收。
