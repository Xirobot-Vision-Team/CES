# EC345 — 已签补件挑战、可见接收方签名回复与有界披露结果

Historical record names below are archival references; those files are absent
from this source tree. See [cleanup scope](../docs/CLEANUP.md).

**CES V6.55 / R345 / EC-345，2026-10-25。** 本 EC 只处理前轮 EC344 审计明确列出的
`claimed_visible_but_not_presented_item_ids`。签名挑战、签名声明、出示原件三者互不替代。
任何正向审计仍返回 **`exit_code=2` / `*_unresolved`**；所有真验工作均为离线样本审计，
不授予真实机构权限、全局缺件结论、已送达事实或 Provider/CAS/WORM 执行能力。

## 1. 信任与角色 — 必须区分

| 原件层 | 精确绑定 | 谁签/谁固定 SHA | 能够证明什么 |
| --- | --- | --- | --- |
| EC343 受信 roster + EC344 directory/checkpoint | roster SHA + directory SHA + checkpoint SHA + round nonce | 由独立保管者从其他可信渠道传入整原字节 SHA；本工具不自授权 | EC343 原注册身份、最多8个公告项及对应 snapshot/ack-set 原 SHA；单独的外部目录差异不会创造新的签署人 |
| EC344 真实 signed views | 2–8个完整视图整原 SHA，至少2个注册接收人真签 | 不同 receiver 的 Ed25519，文件 SHA 必须分别独立固定 | 只确认哪位 receiver **声称**见过哪个 item/SHA |
| EC345 **挑战** | 单 item ID/slot、两个原件路径+SHA、EC344 view SHA 有序集、基线已出示项、anchor、挑战接收名录、attempt 1..3、前一完整挑战 SHA、nonce、时间 | **EC343 change_proposer** 使用自己的 Ed25519 私钥；该挑战的完整 raw SHA 由审计者另行独立固定 | 提出了一个具体的离线补件请求；不构成机构命令或真实送达 |
| EC345 **接收方答复** | 精确 challenge 整原 SHA、目标两个原 SHA、注册 receiver 身份、唯一 nonce、自报 UTC、独立签名域 | 被该挑战明确列名的**原 EC343 接收方**各自 Ed25519 真签；每份 raw SHA 另外固定 | `offer_disclosure` 是答应/声称可以出示；`unavailable_claim` 是该签署人自己的不可用声明 |
| **实际披露文件** | 审计者显式传入 `--disclosed-item-id` 的已公告绝对路径；严格匹配 checkpoint 中两个原 SHA | 本机真实打开文件，检查整原 SHA、EC343 变更/批准/接收历史和 EC342→EC337 真签/ZIP | 只证明**这次出示的**原始字节与固定 SHA 相符、完成要求的本地历史重演；不推断源头身份或物理 custody |

EC345 的新签署域分别是 `CES/EC345/OneItemDisclosureChallenge/v1\0` 和
`CES/EC345/ReceiverDisclosureResponse/v1\0`，**不复用** EC343/344 签名域。
签署对象只包含精确的 `claim` canonical JSON；通过公钥和签名认证，并不是信任谁声称自己已经签过名。

## 2. 轮数与不可混淆规则

- 每份 challenge **只覆盖一项** EC344 已签视图确实声称可见、但基线 `audit-views` 未出示的 checkpoint item；必须保留同一 anchor 和同一组基线已出示项。
- 一项最多 **3 轮**，全报告最多 **8 份**挑战；第 N 轮必须指向第 N−1 轮实际签署原件的完整 SHA，且 item、两份原 SHA、接收人、view 来源等上下文都完全不变。所有轮按 checkpoint 的 item 顺序，再按 1、2、3 递增提供。不同轮挑战 nonce 全局不得复用。
- 每轮至少列 **2 个** EC343 原注册 receiver（最多4个），每人最多 **一份**答复。最多32份签名答复，所有 nonce 跨挑战及答复不可复用。接收人不可代为签发挑战；change_proposer 不可冒充 receiver。
- 签署时间是签署者**自报**：视图签署时间 ≤ 挑战签署时间 ≤ 自报答复时间 ≤ **本轮独立给定的**披露评估 UTC。它们并非可信时间公证，也不是远端系统时钟。
- 报告必须完整给出每项的挑战整原 SHA、答复 SHA、receiver ID、签名种类、轮号、未答复轮次、是否真的出示并验过原件。`signed_unavailable_claim` 和 `request_unanswered` 不代表世界上不存在该文件。
- **相反答复**需有至少两名不同注册 receiver 的真签，对相同被挑战 item 在有界轮次内分别声称 `offer_disclosure` / `unavailable_claim`；冲突优先显示，不报告欺诈、赢家或强制送达。不同自报时间的意见也可能确实改变，不自动认定欺骗。
- 只在有 `offer_disclosure` 真签、审计者又**显式列出该 item** 且完整 SHA + EC343→337 历史真验通过后才叫 `delivered_and_full_raw_sha_verified`；仅签署 offer **永远不算**已交付。出示路径消失、SHA 错误、签名坏或历史不完整时拒绝审计，不自动修复。

## 3. 分离操作入口

两条执行入口：

```bash
python -I -B scripts/ces_cas_disclosure_challenge.py issue-challenge --help
python -I -B scripts/ces_cas_disclosure_challenge.py sign-response --help
python -I -B scripts/ces_cas_disclosure_challenge.py audit-disclosures --help
```

### A. 签发第1轮

示例仅说明命令格式，`/absolute/...`、SHA、时间必须由实际持有者填入，不能照抄示例当受信值。

```bash
python -I -B scripts/ces_cas_disclosure_challenge.py issue-challenge \
  --out /absolute/private/challenge-1.json \
  --private-key-file /absolute/private/ec343-change-proposer.key \
  --roster-file /absolute/roster.json --expected-roster-sha256 "$ROSTER_SHA" \
  --directory-file /absolute/directory.json --expected-directory-sha256 "$DIRECTORY_SHA" \
  --checkpoint-file /absolute/checkpoint.json --expected-checkpoint-sha256 "$CHECKPOINT_SHA" \
  --view-file /absolute/view-receiver-a.json --expected-view-sha256 "$VIEW_A_SHA" \
  --view-file /absolute/view-receiver-b.json --expected-view-sha256 "$VIEW_B_SHA" \
  --anchor-item-id base --baseline-presented-item-id base \
  --item-id missing-item --audience-receiver-id receiver_a \
  --audience-receiver-id receiver_b \
  --attempt-number 1 --challenge-nonce-sha256 "$NEW_64_LOWER_HEX_NONCE" \
  --issued-utc 2026-10-25T20:00:00Z
```

**第2或第3轮**另传 `--previous-challenge-file /absolute/private/challenge-1.json`
和 `--expected-previous-challenge-sha256 "$INDEPENDENT_PREV_CHALLENGE_SHA"`；
增加 `--attempt-number`，换全新 nonce 和输出路径。验证器会读取**整个前序签名挑战链**。
若更改目标/原件 SHA/view/名录/anchor，必须视为另一件新候选，不能伪装成连续补件。

### B. 由不同接收方分别签字

```bash
python -I -B scripts/ces_cas_disclosure_challenge.py sign-response \
  --out /absolute/private/receiver-a-reply.json \
  --private-key-file /absolute/private/receiver-a.key \
  --roster-file /absolute/roster.json --expected-roster-sha256 "$ROSTER_SHA" \
  --directory-file /absolute/directory.json --expected-directory-sha256 "$DIRECTORY_SHA" \
  --checkpoint-file /absolute/checkpoint.json --expected-checkpoint-sha256 "$CHECKPOINT_SHA" \
  --challenge-file /absolute/private/challenge-1.json \
  --expected-challenge-sha256 "$EXTERNALLY_PINNED_CHALLENGE_SHA" \
  --response-kind offer_disclosure \
  --response-nonce-sha256 "$NEW_64_LOWER_HEX_RESPONSE_NONCE" \
  --reported-utc 2026-10-25T20:03:00Z
```

`--response-kind` 只能是 `offer_disclosure` 或 `unavailable_claim`。
即使签了 `offer_disclosure`，也必须等到审计显式出示 **两份原件** 后才可能返回“完整 raw SHA 已验”。
所有候选写入均使用旧 EC343 现有的私有 `0600`、非覆盖 `O_EXCL`、`fsync` 写法；
若目标路径已经存在不会覆盖。`candidate_original_raw_sha256` 只是本机计算值，**不是外部保管确认**。

### C. 最终只读重演

```bash
python -I -B scripts/ces_next.py audit-disclosure-gaps \
  DeliveryAudit AuditSignedDisclosureChallenges --help
```

需完整提供 EC344 `audit-receiver-visibility` 之前所有的前序信任参数（EC341
manifest/root SHA/epoch/评估 UTC、EC342 governance/review/approval 原件 SHA、
EC343 roster/head snapshot/ack set/hold/timeline 评估 UTC、
EC344 directory/checkpoint/anchor/2..8 view pairs/基线已出示 item 集）；
再提供 `--disclosure-evaluation-utc`、1..8 对
`--challenge-file / --expected-challenge-sha256`、
零至32对 `--response-file / --expected-response-sha256`、
零至8个 `--disclosed-item-id`。

**只有这条统一路由**被添加到 `scripts/ces_next.py`：
它固定启动 `python -I -B scripts/ces_cas_disclosure_challenge.py audit-disclosures`，
有强制参数/返回 JSON 边界检查，**不接收** `private-key-file`、`issue-challenge`、
`sign-response`、远端 CAS/WORM 参数或 Provider 写操作。

## 4. 最终结果及排序

| `item_outcomes[].result_kind` | 必须实际发生 | 禁止推断 |
| --- | --- | --- |
| `two_receiver_conflicting_response` | 至少两名不同 EC343 receiver 对该项在提交的有界轮次内有不同签名 kind | 不是欺诈定性；可能同时有原件真验 |
| `delivered_and_full_raw_sha_verified` | signed offer + **显式提交**+ 两份整原 SHA 正确 + EC343/342→337 真历史重演 | 不证明远端物理交付、机构持有 |
| `signed_unavailable_claim` | 至少一份受挑战的原 receiver 真签 unavailable，未形成前两种状态 | 不证明文件已经消失 |
| `signed_offer_but_originals_not_furnished` | 至少一份真签 offer，但审计未拿到/未指定原文件 | 签名 offer 不等于文件 |
| `request_unanswered` | 该项已有实际真签挑战，提交的本次样本没有任何真签答复 | 不是所有收件人都不回应的全球证明 |

报告总 `status` 按表中优先级选最显著的 `*_unresolved`，但
`item_outcomes` 和 `outcome_counts` **保留全部项目的不同结果**，不以总状态抹掉缺口。

## 5. 限制及后续统一人工验证

1. 真实机构人员身份、公钥与私钥硬件隔离、真正独立的 whole SHA custody 和 UTC 时间来源，均没有通过离线测试认证。
2. EC344 独立 receiver directory 不等于完整全球收件名录；没有远端通知、无已读回执、无 Provider/CAS/WORM freeze/release/readback/nonexecution，也没有分叉赢家裁决。
3. 在已有 EC343→337 的深层 EC317/318 历史 fixture 中仍存在 **MOCK**；本 EC 真运行链路不等于全旧生产历史去 MOCK。
4. 原生 PowerShell 7、旧15套 Smoke、Windows/macOS/Git/CI/Provider、E63–E66 性能/资源安全以及最终用户联合验收需集中辅助验证。EC249 incompletion、EC250 BLOCKED、B-001 OPEN、Quality PASS=false、final NOT_STARTED 不变。

本轮本地开发核验及精确未验项目见
`EC345_LOCAL_REPORT.json` 和
`EC345_SCOPE.json`。
