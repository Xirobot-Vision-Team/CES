# EC301 — 离线发送方 Offer / 接收方签收、逐次可重放交接链

本文件描述 **V6.11 / R301 / EC301** 的真实边界和可执行入口。原 EC300 是“两个见证私钥共同签署一个已核验的比对会话”，EC301 进一步对**向对方传递了哪个 EC300 完整历史版本**提供独立的 sender offer → recipient ACK 仪式和 1～8 次交接的精确 SHA 链。它不包含网络通信、自动跨机复制或远端存储。

## 0. 准备工作、信任边界和磁盘路径

- 先在发送方、接收方各自机器上准备可完整复验的原 EC294→300 来源文件，尤其是本机**绝对路径**的 EC300 full history JSON、其中每次会话引用的 EC299 witness manifest、完整 EC297 epoch/bridge/EC295 policy/checkpoint/原 EC294 真实签回。原始 EC300 JSON 中的绝对路径**不可原样假定**在另一台机器有效；必须在各自机器上重建本机路径指向**相同原内容**，然后重新验证外部指定的 SHA。不要把含私钥、原始 HMAC 或生产凭据的目录作为传输工件。
- 外部可信介质分别留存两位见证 ID、公钥、最新 EC299 A/B 观察 SHA、最新 EC300 session SHA、**最新 EC301 receipt SHA**；旧链继承时另外留存上一次 A/B/session/receipt 四 SHA。没有真正的独立外部托管时，命令只是**核验调用方提供的 SHA**，不能自证未曾整链回退。
- 使用两把不同的原 EC299 witness Ed25519 私钥；发送方只用选定的 A 或 B 私钥，接收方只用相反角色的私钥。以 EC301 专门签名域分别签 `sender + 完整 claim` 和 `recipient + 完整已签 offer`。原 EC300/299 签名不被重写，原业务 Host/Provider 不被调用。签名时私钥应放在独立管控、0600 的安全文件中，不要作为 JSON 字段或 CLI 参数提供。
- 每次交接需要独立取得 **64 位小写十六进制非零 challenge SHA**，不要认为普通软件伪随机值提供硬件或组织挑战权威、可信 UTC。

## 1. 协议的两个签章

- `prepare-offer`：以独立输入的完整原 EC300 history 和四个初始 pin（A/B ID、公钥、A/B 最新观察 tip、最新 session tip）**先完整重放**每一个原 EC294→300 签名材料。若非首轮，另以 `prior-journal-file` 及独立前一回执 + A/B/session 的四个 SHA 全量重验旧交接历史。生成 **未签**草案（不能当作发送证明）。
- `sign-offer`：重做上述全部重验，读取 `--expected-draft-sha256` 所指定的草案，逐字节 canonical 重算 claim；校验发送私钥对应**指定 sender role** 的原 EC299 公钥，输出只包含 claim 与签名的**已签** offer。
- `accept-offer`：接收侧自行备齐本地原 EC300 完整证据，重做原始历史与旧交接链核验；先核实从可信带外渠道获得的 `--expected-offer-sha256`，再验证发送者签名与全部 parent 原文重算 claim 一致；接收侧用另外一个原 EC299 公钥签出**包含原 offer 全部原样 canonical 内容**的 ACK。该 receipt 是完整交接证据，独立保管其 SHA。三个制件阶段即使签署了包含真实 fork 的历史，输出也单独显式携带 `historical_comparison_status` / `historical_comparison_exit_code`；制件命令返回 `0` 只表示制件操作完成，**不是**原历史相容或业务成功。
- 后续交接必须传入**完整旧 journal**，每张已签 receipt 与原 EC300 源证据重新复验；新的原 EC300 会话 SHA 数组必须严格保留以前**全部旧成员作为前缀**且长度真正增长，两条已签 witness receipt SHA 观察历史不能缩短、替换或重排。EC301 challenge 不能跨 journal 历史复用，交接序号 `1..8` 不可跳号。Sender 可以 A/B 交替，recipient 始终是同轮相对的一方，两把公钥和原审计身份跨链固定。
- `verify-journal` 返回 `0` 仅表示给定历史的签章与完整证据一致、没有在已提供历史发现冲突；从任意一轮已发现签名竞争或者历史不确定得到 `2`；校验失败是 `3/4/5`，不得把拒绝当 `0`。`verify-report` 要求单独来源的报告 SHA，逐字段全链重算。报告去除本机文件路径，仅输出摘要/公钥/角色/状态。

## 2. 实际 CLI 运行范式

将示例中的 `$HISTORY` 等替换为本机**绝对路径**。先根据原 EC300 使用指南准备好来源证据和外部 pin。下面是第一轮 sender A → recipient B 的三个阶段，**不自动完成中间实体文件复制**：

```bash
# 在 A 机器：变量必须来自带外可信记录，不能“从待验证文件自动发现可信最新值”。
COMMON=(
  --history-file "$HISTORY"
  --expected-a-id "$A_ID" --expected-a-public-hex "$A_PUB" --expected-a-tip "$A_TIP"
  --expected-b-id "$B_ID" --expected-b-public-hex "$B_PUB" --expected-b-tip "$B_TIP"
  --expected-session-tip "$SESSION_TIP"
  --sequence 1 --sender-role a
  --exchange-challenge-sha256 "$INDEPENDENT_CHALLENGE_SHA"
)
python3 scripts/ces_anchor_handoff.py prepare-offer "${COMMON[@]}" \
  --out /private/ec301-draft.json

# 信任草案 SHA 的独立取得值，发送方本地私钥只在本地读取。
python3 scripts/ces_anchor_handoff.py sign-offer "${COMMON[@]}" \
  --draft-file /private/ec301-draft.json \
  --expected-draft-sha256 "$DRAFT_SHA" \
  --private-key-file /private/a-witness-ed25519.key \
  --out /private/ec301-sender-offer.json

# 将已签 offer 与可重建的原历史证据经人工批准的离线介质交给 B；
# 在 B 机器重设 COMMON 中的 --history-file 为 B 的本机路径并严格保留内容 pin。
python3 scripts/ces_anchor_handoff.py accept-offer "${COMMON[@]}" \
  --offer-file /private/ec301-sender-offer.json \
  --expected-offer-sha256 "$EXTERNALLY_CUSTODIED_SENDER_OFFER_SHA" \
  --private-key-file /private/b-witness-ed25519.key \
  --out /private/ec301-receiver-signed-receipt.json
```

**输出权限**：草案、offer、ACK 与可选报告全用原 EC295 0600、`O_EXCL`、file `fsync` + parent-dir `fsync` 原语保存。现有文件不覆盖；命令不会复制任何原始证据或者调用网络 API。必要时使用 shell `sha256sum` 核对每个可信 pin，注意源文件 raw SHA 与 canonical JSON SHA 的区别：EC301 的 draft/offer/receipt/report pin 都是原 `a.sha(JSON)` 规范化摘要，不能将尾换行计入 SHA。

## 3. 创建并核验完整交接 journal

人工生成下列 JSON 结构，必须引用**可重验且完整的每轮原 EC300 history**，每项四个 SHA 必须先由独立可信渠道确认。首轮只有一个 `entries`；第二轮必须包含**完整旧 entries 列表**及当前新成员，不能只交最新 receipt：

```json
{
  "schema":"ces.ec301.complete_offline_handoff_receipt_journal.v1",
  "a_id":"separate_site_alpha",
  "a_public_hex":"<64-hex externally pinned A public key>",
  "b_id":"separate_site_beta",
  "b_public_hex":"<64-hex externally pinned B public key>",
  "entries":[
    {
      "signed_receipt_file":"/private/round-1-receipt.json",
      "expected_receipt_sha256":"<64-hex independently retained receipt digest>",
      "ec300_history_file":"/private/round-1-full-ec300-history.json",
      "expected_a_tip":"<64-hex witness A observation digest>",
      "expected_b_tip":"<64-hex witness B observation digest>",
      "expected_session_tip":"<64-hex latest round-1 EC300 session digest>"
    }
  ]
}
```

```bash
python3 scripts/ces_anchor_handoff.py verify-journal \
  --journal-file /private/ec301-journal.json \
  --expected-a-id "$A_ID" --expected-a-public-hex "$A_PUB" --expected-a-tip "$LATEST_A_TIP" \
  --expected-b-id "$B_ID" --expected-b-public-hex "$B_PUB" --expected-b-tip "$LATEST_B_TIP" \
  --expected-session-tip "$LATEST_EC300_SESSION_SHA" \
  --expected-receipt-tip "$LATEST_EC301_RECEIPT_SHA" \
  --out /private/verified-ec301-report.json

python3 scripts/ces_anchor_handoff.py verify-report \
  --journal-file /private/ec301-journal.json \
  --expected-a-id "$A_ID" --expected-a-public-hex "$A_PUB" --expected-a-tip "$LATEST_A_TIP" \
  --expected-b-id "$B_ID" --expected-b-public-hex "$B_PUB" --expected-b-tip "$LATEST_B_TIP" \
  --expected-session-tip "$LATEST_EC300_SESSION_SHA" \
  --expected-receipt-tip "$LATEST_EC301_RECEIPT_SHA" \
  --report-file /private/verified-ec301-report.json \
  --expected-report-sha256 "$EXTERNALLY_STORED_REPORT_SHA"

# 精确、只读的统一控制台入口（不可签发、ACK 或触发业务写入）：
python3 scripts/ces_next.py audit-handoff DeliveryAudit VerifyHandoff \
  --journal-file /private/ec301-journal.json \
  --expected-a-id "$A_ID" --expected-a-public-hex "$A_PUB" --expected-a-tip "$LATEST_A_TIP" \
  --expected-b-id "$B_ID" --expected-b-public-hex "$B_PUB" --expected-b-tip "$LATEST_B_TIP" \
  --expected-session-tip "$LATEST_EC300_SESSION_SHA" \
  --expected-receipt-tip "$LATEST_EC301_RECEIPT_SHA"
```

第二轮的 `prepare-offer|sign-offer|accept-offer` 须额外提供 `--sequence 2`、真实新 EC300 `--history-file`、新的角色和 challenge，及 `--prior-journal-file`、`--expected-previous-receipt-sha256`、`--expected-prior-a-tip`、`--expected-prior-b-tip`、`--expected-prior-session-tip`，相同参数必须在两个设备独立重验，且源 EC300 会话历史应严格增长。

## 4. 容易误读的边界

- ACK **证明对应私钥在验证路径上对带有已签 offer 的内容签过字**，不证明实际网络收到消息、组织内由哪位真人操作、两把钥匙在不同设备中保管，或远端不可回退的实体保存已经落地；若两把密钥被同一人控制，也可做出相同的有效签章。
- 此轮**未打包可移机全量内容**，只约束独立证据文件和逻辑承诺；EC300 源 JSON 中的绝对路径需要各设备重新绑定。不可用单独的交接 receipt 冒充已经发送完整原始证据。
- EC301 最新 digest、报告 SHA 与 A/B/session pin 必须由独立可靠的线下渠道保留才能用于反回滚判断；如果攻击者同时控制旧源与所有所谓“外部 pin”，仍可以整体回放旧链，代码不能仅靠两个软件签名打破这个限制。
- 本轮不发明可信时间、撤销发行方、HSM 或 WORM、真实传输通道；不修改原 EC225/226/227/294 Host 或原 PowerShell7 业务路径；不自动检查 Provider/Inbox 生产端状态。
- 即使所有本机聚焦测试通过，EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、总 Quality PASS=false、final `NOT_STARTED` **不变**。最终仍需客户参与跨设备真实验收与 native PowerShell 15 Smoke、CI/Git/Windows/macOS/E63～E66、Provider/Inbox。
