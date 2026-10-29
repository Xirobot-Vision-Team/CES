# EC346 — 真签披露后本地字节收讫、替换/撤销声明链与副本差异审计

Historical record names below are archival references; those files are absent
from this source tree. See [cleanup scope](../docs/CLEANUP.md).

**CES V6.56 / R346 / EC-346，2026-10-25。** 仅本 EC 新增代码。以 EC345 **实际验到两份原件** 的
`verified_furnished_originals=True` 为必要前提，不能把仅签署 `offer_disclosure`、`unavailable_claim`
或 `request_unanswered` 的条目提升成可复制原件。EC345 总状态为接收方观点冲突也可以作为已验原件，
**但仅当该条目确实已显式出示且整原 SHA 与历史原签全部重放成功**。所有输出均 `exit_code=2`、
`*_unresolved`，不形成实际远端授权/跨机送达/物理机独立/法律保管证明。

## 1. 与前轮原件的严格关系

每次新签名或审计重新调用 EC345 `audit_disclosures`，真实重放 EC344→EC343→EC342→EC337 的
受信原件/历史 Ed25519/ZIP 验证；**不能从上一轮文本报告或新签者自述获得可信原件**。

- 上层由独立审计者提供 EC341 发行者根与 epoch 的外部锚、EC342–343 治理/收讫历史原 SHA、
  EC344 directory/checkpoint/已签视图原 SHA、EC345 真签 challenge/response 原 SHA、显式提交原件项、
  独立评估 UTC。旧原 SHA、旧域与路径完全原封不动。
- 本 EC 绑定 `ec345_full_audit_arguments_canonical_sha256`（完整审计参数规范 JSON SHA）、
  原 roster/directory/checkpoint SHA、全部挑战/答复 SHA 有序清单，及所选 item 的原 snapshot 与
  ack-set **完整原 SHA、路径和 slot**。新签名域
  `CES/EC346/OfflineReceiverCopyObservation/v1\0`，不复用旧域。
- 真签者只能是**原 EC343 受信 roster 中被该 EC345 挑战列名的 receiver**，使用其已有独立
  Ed25519 私钥。一个接收人仅代表自己的本地声明；签名不自动证明机构合法身份、机器隔离或
  真正的其他网络、磁盘、远端保管物。

## 2. 三种有界不可篡改的观察事件

| `event_kind` | 生成时会做什么 | 不意味着什么 |
| --- | --- | --- |
| `receipt`（序号1） | 签署程序真实打开另一个**私有、普通单硬链、0600** 的 snapshot 副本和 ack-set 副本，计算两份原字节 SHA+长度，记录与 EC345 原 SHA 是否一致，真签“我观察了这些字节”的局部声明 | 不代表远端物理送达、全副本长期可读、不可伪造的机器身份 |
| `replacement_claim`（序号2或3） | 必须链接相同接收人、同一 copy/storage label 和上一份**真签整原 SHA**；重新实读新的两份副本并记录变化 SHA | 不能回写旧 signed receipt 或旧 EC345 原始 snapshot |
| `revocation_claim`（序号2或3） | 必须链接实际存在的上一份真签，保留**最后一次已测量**的副本 SHA/长度/路径，事件本身**不触碰副本字节** | 只表示收件人声称撤回/不再担保，不是擦除文件、远端撤销、CAS/WORM 解冻或无执行证明 |

同一 receiver 最多3个事件、最后一个 `revocation_claim` 后不可续签；提交样本最多12份事件，
必须有至少2名不同的原注册 receiver 的真实首个 `receipt`。所有原件单独提供独立 whole SHA，
每位 receiver 的所有上游事件也必须在审计列表中**原 SHA 完整、序号连续、按原 roster 顺序分组**。
任何事件 nonce 在本次所有 EC345 challenge/response 和 EC346 events 内全局不得复用；
自报 UTC 不得早于已给 EC345 评估 UTC、晚于本轮接收审计 UTC、或在同人链中逆序。
原文件及签名都 owner-private/O_EXCL/fsync；不得用输出路径覆盖输入文件。

## 3. 不能隐式打开签名指向的接收机路径

审计新参数中 `--presented-receiver-id`、`--presented-snapshot-file`、`--presented-ack-set-file`
三列**按一一配对的顺序**提交；只打开用户本轮显式提供的副本，且绝对路径必须等于对应 receiver
最后一个有界签名事件保留的 snapshot/ack-set 路径。未列出的副本：**完全不打开、不扫描**，
返回 `signed_copy_not_presented_in_this_audit`。列出后全部真正读取并计算 SHA，保留三种区别：

1. **与签名中 SHA/长度不匹配**：`presented_copy_changed_since_signed_observation`。
2. **与签名 SHA/长度一致，但与 EC345 已验来源不同**：
   `presented_copy_differs_from_verified_source`；例如签名时已见到的不同 bytes。
3. **与签名和已验来源两者均一致**：`presented_copy_matches_verified_source`。

可同时有不同 receiver 的正向/异常结果；报告保留 `receiver_copies[].signed_event_history`
（逐版 SHA、前驱 SHA、自报 UTC、所测两份 SHA、是否测量）和跨 receiver 的
`signed_copy_sha_difference_receiver_pairs`、
`explicitly_measured_copy_sha_difference_receiver_pairs`、
`same_claimed_storage_label_receiver_pairs`。两个不同签名接收人使用了相同 storage label 会被明确列出；
即使 label 不同也无法证明独立物理机器、全局可用性或已分配的真实权限。

总状态按优先级展示最突出缺口（逐项原结果始终不丢）：
`presented_copy_changed_since_signed_observation_unresolved` →
`presented_copy_differs_from_verified_source_unresolved` →
`revocation_or_replacement_claim_unresolved` →
`signed_copy_not_presented_in_this_audit_unresolved` →
`multiple_identical_local_copies_unresolved`。
**最后一种只是离线局部 hash 比较通过，不是 FINAL PASS。**

## 4. 操作入口与权限

独立签署子命令和只读审计子命令：

```bash
python -I -B scripts/ces_cas_disclosure_custody.py sign-observation --help
python -I -B scripts/ces_cas_disclosure_custody.py audit-copies --help
```

只读统一控制台唯一新增路由：

```bash
python -I -B scripts/ces_next.py audit-disclosure-copies \
  DeliveryAudit AuditPostDisclosureReceiverCopies --help
```

需要先从 EC345 原有 `audit-disclosures` 操作指南整理**完全一致的全部原始验证参数**
（EC344 的 `--manifest-file`/`--expected-manifest-sha256` 等全部标量，
`--view-file/--expected-view-sha256`、`--challenge-file/--expected-challenge-sha256`、
`--response-file/--expected-response-sha256`、
`--presented-item-id/--disclosed-item-id` 等多值），并在每次 EC346 调用中原样提供。
不能填写这里没有提供过的“预设受信 SHA”。`$BASELINE_ARGS` 在下面只是操作员填入的 Shell 数组示意，
**并非自动生成的证据**。

由 receiver A 用其**原 EC343 注册的私钥**签第一个实际字节观察：

```bash
python -I -B scripts/ces_cas_disclosure_custody.py sign-observation \
  "${BASELINE_ARGS[@]}" \
  --item-id rev --copy-id receiver_a_copy --claimed-storage-id site_a_claim \
  --out /private/receiver-a-first-event.json \
  --private-key-file /private/receiver-a.key \
  --event-kind receipt --sequence 1 \
  --event-nonce-sha256 "$EXTERNALLY_CHOSEN_FRESH_64_HEX" \
  --reported-utc 2026-10-25T20:40:00Z \
  --copy-snapshot-file /private/receiver-a-snapshot-copy.json \
  --copy-ack-set-file /private/receiver-a-ack-copy.json
```

Receiver B 通过自己的**不同**原注册私钥、独立目录和不同 copy id 签同样种类的 `receipt`。
真正二版替换必须提供：

```bash
--event-kind replacement_claim --sequence 2 \
--previous-event-file /private/receiver-a-first-event.json \
--expected-previous-event-sha256 "$INDEPENDENT_FIRST_EVENT_WHOLE_SHA" \
--copy-snapshot-file /private/replacement-snapshot.json \
--copy-ack-set-file /private/replacement-ack.json
```

二版/三版 `revocation_claim` 改成**不传两份新的副本路径**：仅提供前版
`--previous-event-file/--expected-previous-event-sha256`，不调用远端删除。

双接收人本轮只读比较（事件文件和 SHA 必须按原 EC343 roster 中 receiver 顺序，
有第2/3版时同一 receiver 的各版先按序列完整排列）：

```bash
python -I -B scripts/ces_next.py audit-disclosure-copies \
  DeliveryAudit AuditPostDisclosureReceiverCopies \
  "${BASELINE_ARGS[@]}" \
  --item-id rev --custody-evaluation-utc 2026-10-25T20:50:00Z \
  --observation-file /private/receiver-a-first-event.json \
  --expected-observation-sha256 "$INDEPENDENT_RECEIVER_A_EVENT_SHA" \
  --observation-file /private/receiver-b-first-event.json \
  --expected-observation-sha256 "$INDEPENDENT_RECEIVER_B_EVENT_SHA" \
  --presented-receiver-id receiver_a \
  --presented-snapshot-file /private/receiver-a-snapshot-copy.json \
  --presented-ack-set-file /private/receiver-a-ack-copy.json \
  --presented-receiver-id receiver_b \
  --presented-snapshot-file /private/receiver-b-snapshot-copy.json \
  --presented-ack-set-file /private/receiver-b-ack-copy.json
```

上述示例中的 receiver_id、路径、原 SHA、UTC、nonce 都要以实际创建的原件为准。
签署 CLI 可新建私有签名候选，但**统一控制台只执行固定 `python -I -B audit-copies`**，
拒绝携带签署私钥、任意 writer/installer/provider/CAS/WORM 操作。
参数解析错误的进程可能同为 shell exit 2，**必须看是否输出 schema/status 正确的 JSON**，
不可单以进程码 2 当作“已验成功”。

## 5. 局部事实、人工联验缺口

本机聚焦真实签名/真实字节读回 **26/26 PASS**，EC345 **20/20**、EC344 **12/12**、
EC343 **20/20** 独立回归通过。覆盖独立真签、多收件人真实与缺席副本、签名时不同字节、
签后字节漂移、替换/撤销回执、前驱/重放/nonces、伪造合法签名后的 EC345 nonce 复用、
角色越权、禁止原件路径别名、固定隔离只读路由与真实 CLI。旧深层 EC317/318 仍来自
**MOCK fixture**，没有跑 EC342 及更早全套集成，不能升级为无 MOCK 全生产验证。

真实机构和硬件密钥独立控制、可信 UTC 与完整撤销表、由外部独立机构固定 SHA、两台物理机器
字节副本/持久性、完整全球 receiver/所有隐藏分叉/latest/winner、真实 Provider/CAS/WORM
freeze/release/readback/nonexecution、原生 PowerShell 7 及旧 15 Smoke、Windows/macOS/Git/CI、
E63–E66 和用户统一验收均需最后人工辅助；当前 **NOT_PROVEN/NOT_RUN**。EC249 incomplete、
EC250 BLOCKED、B-001 OPEN、Quality PASS=false、final NOT_STARTED **继续保留**。

`范围` · `局部事实` ·
`全工程原 SHA`。
