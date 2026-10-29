# EC299 — 双见证离线签名观察链、跨历史一致性核对与分叉留证

Historical record names below are archival references; those files are absent
from this source tree. See [cleanup scope](../docs/CLEANUP.md).

## 身份和限制

- 本轮完整包版本 **V6.09 / R299 / EC299**，只施工本 EC。
- `construction/witness_consistency/witness.py` 是离线验证核心；`operator.py` 是私有文件签署/比对工作流；独立入口 `scripts/ces_anchor_witness.py`；统一控制台**仅**允许 `audit-witness DeliveryAudit VerifyWitnesses`。
- **两个不同 Ed25519 公钥**各自签署 1–8 条观察；每条原 EC297 承诺均须给出输入文件和 **commitment / root tip / latest tip / latest bridge SHA** 四项显式 pin。每条原 EC297 的完整 3–16 代原 EC294/EC295/EC296 审计证据在核对时重新验签，且重新检查实际完整 EC295 checkpoint 源文件。
- 两条观察链各自以 `sequence=1, previous_observation_sha256=000...0` 起始，每条后继都必须含前张 **完整签署观察文件的 canonical SHA**；分别要求两位见证的预期 ID、公钥和最新观察 SHA 由操作者从独立可信渠道提供，**不得**使用 `manifest` 自称的最后一项当外部真值。
- 程序可证明数据按某两把公钥签名、原始链可信摘要与路径无关；不能证明真人/设备独立、保管人权限、WORM/异地不可篡改、可信时间、全球唯一最新、没有第三条分支或实际 Provider/Inbox 送达。

## 一、为一位见证者签发第一张观察

1. 准备上一轮 EC297 所需的真实原 EC294/295/296 完整证据文件，依照 EC297 手册生成离线 `inputs.json` 及 commitment.json，并从另一个可信渠道核定四个 SHA。将 witness 的原始 32 字节 Ed25519 私钥以 0600 保护，`witness_public_hex` 是其对应公钥。不同站点必须使用不同 key。**不会在本模块内生成或共享私钥。**
2. 在**有公钥但无私钥**的工作区准备待签稿（须提前创建由操作者控制的 0700 私有父目录；`--out` 不得存在）：

```sh
python3 -I -B scripts/ces_anchor_witness.py prepare-observation \
  --witness-id site_alpha --witness-public-hex "$ALPHA_PUBLIC" --sequence 1 \
  --inputs-file "$INPUTS_ABS" --commitment-file "$COMMITMENT_ABS" \
  --expected-commitment-sha256 "$COMMITMENT_SHA" \
  --expected-root-tip "$ROOT_TIP" \
  --expected-latest-tip "$LATEST_TIP" \
  --expected-latest-bridge-sha256 "$BRIDGE_SHA" \
  --out "$PRIVATE_DIR/alpha-draft.json"
```

3. 将 **draft SHA 单独核对**后，在离线签名环境调用：

```sh
python3 -I -B scripts/ces_anchor_witness.py sign-observation \
  --draft-file "$PRIVATE_DIR/alpha-draft.json" \
  --expected-draft-sha256 "$DRAFT_SHA" \
  --private-key-file "$ALPHA_PRIVATE_KEY_FILE" \
  --inputs-file "$INPUTS_ABS" --commitment-file "$COMMITMENT_ABS" \
  --expected-commitment-sha256 "$COMMITMENT_SHA" \
  --expected-root-tip "$ROOT_TIP" \
  --expected-latest-tip "$LATEST_TIP" \
  --expected-latest-bridge-sha256 "$BRIDGE_SHA" \
  --out "$PRIVATE_DIR/alpha-signed-observation-1.json"
```

签名步骤重新完整核验本条原证据、先核定 draft SHA 再验私钥公钥匹配。输出 0600 独占、不覆盖、fsync 文件及父目录，返回 canonical 签署观察 SHA。**签署不等于已将 SHA 保存在独立、不可回退的地方。** 应由外部见证方自行保管并从独立通道提供 pin。

## 二、追加同一见证的后续观察（2～8）

后续签署必须额外提供：`--previous-receipt-file`、`--expected-previous-receipt-sha256` 以及**原前次历史的全部六项文件/pin**，分别写为 `--previous-inputs-file`、`--previous-commitment-file`、`--previous-expected-commitment-sha256`、`--previous-expected-root-tip`、`--previous-expected-latest-tip`、`--previous-expected-latest-bridge-sha256`。其中前次 SHA **必须从独立保管处核定**；当前 `--inputs-file` 等仍描述本次全新历史。`prepare-observation --sequence 2` 与 `sign-observation` 各自必须传入上述附加字段。

签署程序会完整重验前后原 EC297/295/296 签名证据，并要求前次完整 checkpoint 链是本次的**真祖先**，禁止同一公钥签署同一历史的重复“进度”或争议中的不同分叉作为安全推进。验证端也对每相邻观察重新做相同严格检查。已封存的旧 epoch 不可改写；最后一代允许**从真实已签 checkpoint 数组尾部新增**检查点，随后再继续新 epoch 的轮换；比单纯比较两份 commitment SHA 更精确。

签名和各历史验证步骤不调用原 EC294 Host socket、不接入 Provider、不触发 EC225 `/submit`、不读原 HMAC/Token 密钥。只读现成签名证据和待签人的离线 Ed25519 私钥。

## 三、两个站点的比对清单

将来自两个独立渠道的公钥、最新观察 SHA 和全部已签观察及原证据按以下结构放在**非共享私钥**的本地工作区。所有文件路径必须是绝对路径，全部原 EC297 SHA 都需要指定：

```json
{
  "schema": "ces.ec299.two_witness_observation_manifest.v1",
  "a": {
    "witness_id": "site_alpha",
    "observations": [{
      "signed_observation_file": "/absolute/a-signed-1.json",
      "inputs_file": "/absolute/a-inputs-1.json",
      "commitment_file": "/absolute/a-commitment-1.json",
      "expected_commitment_sha256": "<64-lowercase-hex>",
      "expected_root_tip": "<64-lowercase-hex>",
      "expected_latest_tip": "<64-lowercase-hex>",
      "expected_latest_bridge_sha256": "<64-lowercase-hex>"
    }]
  },
  "b": {
    "witness_id": "site_beta",
    "observations": [{
      "signed_observation_file": "/absolute/b-signed-1.json",
      "inputs_file": "/absolute/b-inputs-1.json",
      "commitment_file": "/absolute/b-commitment-1.json",
      "expected_commitment_sha256": "<64-lowercase-hex>",
      "expected_root_tip": "<64-lowercase-hex>",
      "expected_latest_tip": "<64-lowercase-hex>",
      "expected_latest_bridge_sha256": "<64-lowercase-hex>"
    }]
  }
}
```

此处尖括号仅是占位文字，必须替换为真实值（绝不能以本地 JSON 内容自行充当可信外部 pin）。每站点最多 8 张有序观察；只允许真实同任务、相互关联的原完整历史。

```sh
python3 -I -B scripts/ces_anchor_witness.py compare-witnesses \
  --manifest-file "$MANIFEST_ABS" \
  --expected-a-id site_alpha --expected-a-public-hex "$ALPHA_PUBLIC" \
  --expected-a-tip "$ALPHA_EXTERNALLY_STORED_OBSERVATION_TIP" \
  --expected-b-id site_beta --expected-b-public-hex "$BETA_PUBLIC" \
  --expected-b-tip "$BETA_EXTERNALLY_STORED_OBSERVATION_TIP" \
  --out "$PRIVATE_DIR/comparison-report.json"
```

若无需写报告，使用精确只读统一控制台（参数相同但多 `DeliveryAudit VerifyWitnesses` 两项）：

```sh
python3 -I -B scripts/ces_next.py audit-witness DeliveryAudit VerifyWitnesses \
  --manifest-file "$MANIFEST_ABS" \
  --expected-a-id site_alpha --expected-a-public-hex "$ALPHA_PUBLIC" \
  --expected-a-tip "$ALPHA_EXTERNALLY_STORED_OBSERVATION_TIP" \
  --expected-b-id site_beta --expected-b-public-hex "$BETA_PUBLIC" \
  --expected-b-tip "$BETA_EXTERNALLY_STORED_OBSERVATION_TIP"
```

对两站点所有历史观察运行 **N×M** 比较，而不只比较最新观察。精确共同签名父节点的 EC295/296 fork 是客观双份已签竞争证据；无法证明同父时只能 `inconclusive`。所有无冲突的同历史/已验真祖先延长仅说明**提交的这两组历史**一致，不代表全局不存在其他分叉，更不自动选“全网最新”。

返回码：`0` 提交证据相容；`2` 发现真实已签竞争证据或无法确定先后；`3` 权限/外部锚点不匹配；`4` 输入格式/边界错误；`5` 文件、加密组件或其他环境不可用。**无论返回什么，均不升级生产送达或全局信任。**

## 四、带外报告 SHA 再验证

`compare-witnesses --out` 仅把无本地文件路径的摘要报告以私有方式输出，不包含全部原始签名文件。由**另一个独立保管渠道**保存报告 SHA。重放全部验证时：

```sh
python3 -I -B scripts/ces_anchor_witness.py verify-report \
  --manifest-file "$MANIFEST_ABS" \
  --expected-a-id site_alpha --expected-a-public-hex "$ALPHA_PUBLIC" \
  --expected-a-tip "$ALPHA_EXTERNALLY_STORED_OBSERVATION_TIP" \
  --expected-b-id site_beta --expected-b-public-hex "$BETA_PUBLIC" \
  --expected-b-tip "$BETA_EXTERNALLY_STORED_OBSERVATION_TIP" \
  --report-file "$PRIVATE_DIR/comparison-report.json" \
  --expected-report-sha256 "$EXTERNALLY_STORED_REPORT_SHA"
```

对比从全部原始历史重新计算后生成的**逐字段完全相同**报告；传入一份本地自行修改的报告及其自己算出的 SHA 并不能改变结论。独立文件保管与现场权限仍由操作者负责。

## 五、边界与本地开发事实

- 两站点见证是两把不同的有效 Ed25519 公钥，不是程序认证的两个人；若两钥实际由同一攻击者控制，可签假定内容但无法伪造未持有钥的原 EC294/295/296 证据。相同人控制外部所有 tip 的整体回退仍不可自动检测。
- 未实现远端 WORM、跨站 gossip / 消息传输、法域审批、签名钥吊销、可信时间、全局一致性证明、未知见证发现或真实外部锚点探测。**绝不声称程序部署了生产多方仲裁。**
- 原 Router **74 路由 / 11 HOST_REQUIRED 拒绝**、原 PowerShell V4.60/R150、原 EC294/295/296/297/298 源码未改。EC299 仅新签名观察与只读一致性对比；没有原业务发送。
- Linux/POSIX 单机的本地真实原 EC294 socket+Ed25519、EC227 HMAC/fsync、EC295 双签、EC296 四签构造了 3 代、4 代及竞争分叉：新 EC299 **30/30** 聚焦用例正常退出；不代表生产 Provider、真正 WORM、实际组织分权、PS7 15 Smoke 或 Windows/macOS 已通过。
- EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、final `NOT_STARTED`、Quality PASS=false 仍然真实存在。

`EC299 施工记录` · `本轮范围` · `本地事实` · `下一轮`。
