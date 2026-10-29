# EC347 — 独立签署挑战后的接收方二次读取与有界持久性声明审计

**施工包 V6.57 / R347 / EC347。** 本协议是一个能真实调用的离线 Ed25519 字节复测功能，并非远程存储系统、文件复制器、法律保全命令或物理独立性鉴定程序。历史 PowerShell CLI 仍为 V4.60/R150。

## 1. 业务能力与前提

- 来源必须是完整、独立原 SHA 固定的 EC346 `audit_copies` 输入：`item_id`、`custody_evaluation_utc`、`observation_files`/`observation_shas`，以及完整 EC345 的目录、原签视图、逐项挑战/答复、已出示原件及 EC342→EC337 等所有原 SHA。EC347 真实重跑 EC346 的已签接收人时间线和 EC345→EC337 原件历史；不能用自述的 `verified=true` 替代真实原签重演。原先已吊销的 EC346 接收方不再具备挑战对象资格。
- **不同角色签名：** 原 EC343 roster 的 `change_proposer` 私钥（与所有登记接收人公钥互不相同）签发 `issue-challenge`。原 EC343 接收人各用自己的原私钥签署 `sign-readback`，且只能回答已签挑战 audience 中的自己的条目；`change_proposer` 不能签接收人回复。签名域 `CES/EC347/IndependentReReadChallenge/v1\0` 与 `CES/EC347/ReceiverReReadResponse/v1\0` 分离，并与 EC343～EC346 的旧域互不混淆。
- **明确限制轮次：** 一个目标最多 3 轮，首轮无前驱、后续严格绑定前轮完整签名文件路径和独立 SHA，受挑战的 2–4 位接收人始终以原 roster 顺序列出且跨轮不暗中换人。新签挑战绑定整个 EC346 审计输入的 canonical SHA、每份 EC346 签名 observation SHA、原件 SHA、每位接收人最后一份已签原件 SHA 和其当时的副本 SHA/长度、独立 challenge nonce、自报 UTC。
- **实际重新读取：** 接收人可选择 `measured_readback`，必须在签名前**显式传入 EC346 上一版已签的两条副本绝对路径**，由独立命令重新读取两个 owner-private 常规文件的真实原始字节，记录 SHA256、长度、对比 EC346 已签字节及 EC345 真已出示原件，并在响应里真签。`unavailable_claim` 完全不读取副本、相关字节 SHA 与长度均为 `null`，不构成全局缺失事实。所有 nonce 与 EC345/346 历史及 EC347 已出示挑战/响应比较；跨尚未出示的外部签名原件不冒充全局唯一。
- **签名及输出边界：** 0600/O_EXCL/fsync 的新独立候选原件，拒绝旧原件路径覆盖、符号链接及硬链别名、非法角色、未列名 audience、跨上下文重放、损坏签名、签名 predecessor 不连续与复制件路径暗换。签名候选报告包含本地算出的原 SHA，但只有**另行可靠地固定该 SHA、并将实际原件及 SHA 一并交给审计方**才构成独立审计输入。

## 2. 真正可调用的三个命令

在 `ces/` 工程目录运行（需要 Python、`cryptography` 与已有 EC337–346 代码）：

```bash
python -B scripts/ces_cas_readback_challenge.py issue-challenge --help
python -B scripts/ces_cas_readback_challenge.py sign-readback --help
python -I -B scripts/ces_cas_readback_challenge.py audit-readbacks --help
```

以上三命令均需要全量 EC346 父级信任参数及两组 `--observation-file`/`--expected-observation-sha256`；不能只交一份 receipt 概要。所有旧单值参数继续复用原 EC346 CLI 名称（例如 `--expected-roster-sha256`、`--disclosure-evaluation-utc`、`--custody-evaluation-utc`）。旧多值参数仍为 `--challenge-file`/`--expected-challenge-sha256` 等；**EC347 新挑战不复用旧 EC345 的参数名**，具体新增项：

| 命令 | 新增必填参数 | 可选或重复参数 |
|---|---|---|
| `issue-challenge` | `--out`、`--private-key-file`、`--round-number`、`--challenge-nonce-sha256`、`--issued-utc` | 至少 2 个 `--audience-receiver-id`；第 2/3 轮须 `--previous-challenge-file` 和 `--expected-previous-challenge-sha256` |
| `sign-readback` | `--out`、`--private-key-file`、`--signed-readback-challenge-file`、`--signed-readback-challenge-sha256`、`--response-kind`、`--response-nonce-sha256`、`--reported-utc` | 对 `measured_readback` 两个 `--copy-snapshot-file` / `--copy-ack-set-file` 必填；`unavailable_claim` 时二者**不得**提供 |
| `audit-readbacks` | `--readback-evaluation-utc` | 1–3 对 `--readback-challenge-file`/`--expected-readback-challenge-sha256`，0–12 对 `--readback-response-file`/`--expected-readback-response-sha256`；最后一轮可选按原 roster 顺序列出成组 `--presented-receiver-id`、`--presented-snapshot-file`、`--presented-ack-set-file` |

完整 Python 函数接口为（先将 `ces/construction` 加入 `PYTHONPATH`，例如 `PYTHONPATH=construction python`）：

```python
from ec347_readback_challenge import readback as ec347

# source: 精确 EC346 audit_copies 的父级参数（去掉该审计特有的 presented_*）
# 由操作者从独立可信原件/SHA 清单填写，不从旧报告自报结果拼接。
challenge = ec347.issue_challenge(
    out=challenge_output, private_key_file=proposer_key,
    audience_receiver_ids=registered_receiver_ids,
    round_number=1, challenge_nonce_sha256=fresh_challenge_nonce,
    issued_utc=claimed_issue_utc, **source)
# 从新生成原件独立记录 whole SHA 和原路径，分发至受挑战接收人。
response = ec347.sign_readback(
    out=response_output, private_key_file=receiver_key,
    challenge_file=challenge_output,
    expected_challenge_sha256=independently_pinned_challenge_sha,
    response_kind='measured_readback',
    copy_snapshot_file=explicit_snapshot_path,
    copy_ack_set_file=explicit_ack_path,
    response_nonce_sha256=fresh_response_nonce,
    reported_utc=claimed_response_utc, **source)
# 另行固定 response whole SHA；审计必须明确传入每份原件及其 SHA。
audit = ec347.audit_readbacks(
    readback_evaluation_utc=claimed_audit_utc,
    readback_challenge_files=challenge_paths_in_contiguous_round_order,
    readback_challenge_shas=challenge_sha_pins,
    readback_response_files=response_paths_in_round_and_roster_order,
    readback_response_shas=response_sha_pins,
    presented_receiver_ids=[],
    presented_snapshot_files=[],
    presented_ack_set_files=[], **source)
```

统一控制台**仅暴露审计子动作**：

```bash
python -I -B scripts/ces_next.py audit-readback-challenges \
  DeliveryAudit AuditChallengedReceiverReadbacks --help
```

补齐原 EC346 父级必填参数后，在此入口使用同样的 EC347 `--readback-*` 重复参数。子进程被固定为 `python -I -B ... audit-readbacks`，输入显式白名单、限制 1–3 次挑战与 0–12 个回复、校验输出协议；不接受 `--private-key-file`、`--out`、`issue-challenge`、`sign-readback`、远端 Provider/CAS/WORM 写入或隐式文件复制。

## 3. 结果字段与验证边界

`per_receiver_round_outcomes` 对**每一轮 × 每个受挑战接收人**保留真签原 SHA、回应有无、回应种类、SHA 与原 EC346/EC345 的差异及是否本轮由审计者显式复读。共六种结果：

1. `signed_readback_matches_prior_and_verified_source`：接收人**已签**新复读 SHA/长度均与旧真签字节和来源一致；非外部持久性证明。
2. `signed_readback_changed_from_ec346_observation`：签的二次实读字节已与上一轮 EC346 观察不同。
3. `signed_readback_differs_from_verified_source`：与旧 EC346 一致但与已验证披露原件不同，区别于签后被篡改。
4. `signed_unavailable_claim_without_byte_read`：只是真签的不可用声明，字节未读。
5. `challenged_receiver_did_not_reply`：在已给出的证据集合里未答复，不推论现实失踪。
6. `later_explicitly_presented_bytes_changed_after_signed_readback`：**仅当审计端本次列出了最后一轮接收人的两份路径，确实再次读字节**后发现与 EC347 最新真签不同。未列出时不会自行打开私有路径，也不会将「未出示」抬升为存储丢失。

最多三轮的同一接收人若至少两次真签复读一致，加入 `claimed_same_bytes_on_two_or_more_distinct_signed_rounds_receiver_ids`。这只能说明本地有界证据声称重复读取一致，不能证明自报 UTC 可信、机器跨实体隔离、长期可靠、全世界所有副本可达，**也不能证明曾发生真实远端 CAS/WORM freeze/release/readback/nonexecution**。所有合法结果一律 `exit_code=2`，并带显式 false 的负能力标志。损坏签名/数据不符合协议则按 `permission_denied/invalid_input/unavailable` 返回 3/4/5，不冒称成功。

## 4. 尚需用户最终联合验证的外部事实

外部独立公钥/机构真身份和私钥硬件隔离、分物理机实际拷贝及重新连接、真正独立整原 SHA 保管、受信独立时间源与可审计的保管日志、完整机构撤销/接收方名录、隐藏分叉与最新全局状态、真实远端 Provider/CAS/WORM、无 MOCK EC317/318 深签名历史、原生 PowerShell7 与15套 Smoke、Windows/macOS/Git/CI、E63–E66 资源性能以及最终联合验收都未被此离线代码证明。EC249 incomplete、EC250 blocked、B-001 OPEN、global Quality=false、final NOT_STARTED 沿用。

源码：[`readback.py`](../construction/ec347_readback_challenge/readback.py) · [`operator.py`](../construction/ec347_readback_challenge/operator.py) · [`tests`](../construction/ec347_readback_challenge/test_readback.py) · [`EC-347.md`](../EC-347.md)。
