# EC322：第七方离线分叉案卷签收 ACK 协议与部署

## 作用域及角色

本轮以 EC321 输出的完整原字节 ZIP 为**唯一证据来源**。第七方身份/Ed25519 密钥必须由真实接收组织的可信制度另行建立（本代码无法保证身份属于不同机构或真实人），**不能**由发送方声明或者从签收 ACK 内自取公钥作为唯一受信依据。

第七签只承认“我在执行签发时（声明）已成功重新复核特定原 ZIP 中**两条仍然冲突**的全部原签名”。第七方不是仲裁机关；不能选择 `left/right`，不能判定全球唯一最新、真正 CAS、合法组织审批、外部时钟或两台物理设备是否独立。`exit=2` 是真叉已验，**不是**普通 `0` 成功状态。收到 `exit=3/4/5` 禁止把 ACK 视为有效。

### 必须独立固定的材料

- 来自既有 EC321 的**12 个包外原 pins**：`case-id`、`witness-id`、`witness-public-hex`、`witness-challenge-sha256`、`expected-witness-sha256`、`expected-left-sha256`、`expected-right-sha256`、`expected-left-head-raw-sha256`、`expected-right-head-raw-sha256`、`expected-genesis-raw-sha256`、`registrar-id`、`registrar-public-hex`。
- EC321 ZIP 整个**二进制文件的**原始 SHA：`expected-bundle-sha256`，与同一文件的私有绝对路径 `bundle-file`。
- 新第七签接收方 `ack-id`、`seventh-receiver-id`、`seventh-receiver-public-hex`、`seventh-receiver-challenge-sha256`，均通过可信**包外**渠道选择/发布。新 challenge 为独立随机 32 字节的 SHA 十六进制值，不重用历史可见挑战。**不**由发送方 ZIP 或新 ACK 自身决定可信身份公钥。
- 签收 ACK 独立整份原 SHA（签发完成后输出的 `signed_receiver_ack_original_raw_sha256`）也应独立由受信渠道固定。ACK 原文件为 0600 canonical LF JSON。

所有私有源路径必须为标准绝对路径，所有原 SHA 为小写 64 hex，公钥为小写 64 hex，身份 ID 为 `^[a-z][a-z0-9_-]{1,31}$`。无需修改 EC321 已签原材料中的任何一个字节。

## 1. 持有第七私钥的实际接收端 attest

**前提：** 已有通过独立渠道核定的 EC321 ZIP+SHA 和全部原 witness/registrar 身份及快照 SHA。另拥有单独生成的第七 Ed25519 私钥原始**32 字节**，位于 owner-only 0600 受信绝对路径；`out` 为仅对 owner 可访问 0700 目录下尚不存在的新路径。**不要**把私钥放进 ZIP 或随 ACK 发回。

```bash
python3 scripts/ces_cas_fork_ack.py attest \
  --bundle-file /private/inbox/ec321-fork-case.zip \
  --expected-bundle-sha256 <EC321_ZIP_64_HEX> \
  --ack-id receipt_case_322 \
  --seventh-receiver-id independent_receiver_seven \
  --seventh-receiver-public-hex <SEVENTH_PUBLIC_64_HEX> \
  --seventh-receiver-challenge-sha256 <NEW_CHALLENGE_64_HEX> \
  --case-id <EC321_CASE_ID> \
  --witness-id <SIXTH_ID> --witness-public-hex <SIXTH_PUB_64_HEX> \
  --witness-challenge-sha256 <SIXTH_CHALLENGE_64_HEX> \
  --expected-witness-sha256 <SIXTH_WITNESS_FILE_SHA> \
  --expected-left-sha256 <LEFT_EC319_SNAPSHOT_RAW_SHA> \
  --expected-right-sha256 <RIGHT_EC319_SNAPSHOT_RAW_SHA> \
  --expected-left-head-raw-sha256 <LEFT_EC319_HEAD_RAW_SHA> \
  --expected-right-head-raw-sha256 <RIGHT_EC319_HEAD_RAW_SHA> \
  --expected-genesis-raw-sha256 <EC319_GENESIS_SIGNED_RAW_SHA> \
  --registrar-id <FIFTH_REGISTRAR_ID> \
  --registrar-public-hex <FIFTH_PUB_64_HEX> \
  --private-key-file /private/keys/seventh-receiver-ed25519.bin \
  --out /private/out/ec322-seventh-signed-ack.json
```

返回 JSON `exit_code=2` + `signed_receiver_ack_original_raw_sha256`；意味着已经**签署了确认原分叉的接收方观察 ACK**，不是推断 CAS 仲裁成功。签发失败时不会把旧不合格链变成可信的新 ACK。对于 `private-key-file` 错密钥，精确匹配预先给定的 `seventh-receiver-public-hex` 失败且不创建 ACK。

## 2. 任何独立的审计方 verify

可在没有签发私钥、没有源机绝对路径映射、没有原 EC319 snapshots 实际文件的另一个位置执行；保留同一个未修改的 EC321 ZIP 原字节、原 ACK 原字节和所有**包外** pins：

```bash
python3 scripts/ces_cas_fork_ack.py verify \
  --bundle-file /private/inbox/ec321-fork-case.zip \
  --expected-bundle-sha256 <EC321_ZIP_64_HEX> \
  --ack-file /private/inbox/ec322-seventh-signed-ack.json \
  --expected-ack-sha256 <ACK_ORIGINAL_RAW_64_HEX> \
  --ack-id receipt_case_322 \
  --seventh-receiver-id independent_receiver_seven \
  --seventh-receiver-public-hex <SEVENTH_PUBLIC_64_HEX> \
  --seventh-receiver-challenge-sha256 <NEW_CHALLENGE_64_HEX> \
  --case-id <EC321_CASE_ID> \
  --witness-id <SIXTH_ID> --witness-public-hex <SIXTH_PUB_64_HEX> \
  --witness-challenge-sha256 <SIXTH_CHALLENGE_64_HEX> \
  --expected-witness-sha256 <SIXTH_WITNESS_FILE_SHA> \
  --expected-left-sha256 <LEFT_EC319_SNAPSHOT_RAW_SHA> \
  --expected-right-sha256 <RIGHT_EC319_SNAPSHOT_RAW_SHA> \
  --expected-left-head-raw-sha256 <LEFT_EC319_HEAD_RAW_SHA> \
  --expected-right-head-raw-sha256 <RIGHT_EC319_HEAD_RAW_SHA> \
  --expected-genesis-raw-sha256 <EC319_GENESIS_SIGNED_RAW_SHA> \
  --registrar-id <FIFTH_REGISTRAR_ID> \
  --registrar-public-hex <FIFTH_PUB_64_HEX>
```

先检 ACK 原 SHA、Ed25519 域和签名、完整内部 pin 均与包外相等；**仍会重新完整执行旧 EC321→EC294 原件验签**，比较从历史真签 reconstrued 的 fork claim 与 ACK 的 claim 完全一致。只有验真分叉才 `exit=2` + `status=independent_seventh_signature_and_entire_original_fork_case_reverified`。若 ACK 是真的、但是旧原证据 ZIP 丢失/错 sha/验原失败，同样拒绝验收。

统一控制台**只有 read-only verify**：

```bash
python3 scripts/ces_next.py audit-fork-ack DeliveryAudit VerifySeventhReceiverForkAck \
  --ack-file /private/inbox/ec322-seventh-signed-ack.json \
  --expected-ack-sha256 <ACK_ORIGINAL_RAW_64_HEX> \
  --bundle-file /private/inbox/ec321-fork-case.zip \
  --expected-bundle-sha256 <EC321_ZIP_64_HEX> \
  --ack-id receipt_case_322 \
  --seventh-receiver-id independent_receiver_seven \
  --seventh-receiver-public-hex <SEVENTH_PUBLIC_64_HEX> \
  --seventh-receiver-challenge-sha256 <NEW_CHALLENGE_64_HEX> \
  --case-id <EC321_CASE_ID> --witness-id <SIXTH_ID> \
  --witness-public-hex <SIXTH_PUB_64_HEX> \
  --witness-challenge-sha256 <SIXTH_CHALLENGE_64_HEX> \
  --expected-witness-sha256 <SIXTH_WITNESS_FILE_SHA> \
  --expected-left-sha256 <LEFT_EC319_SNAPSHOT_RAW_SHA> \
  --expected-right-sha256 <RIGHT_EC319_SNAPSHOT_RAW_SHA> \
  --expected-left-head-raw-sha256 <LEFT_EC319_HEAD_RAW_SHA> \
  --expected-right-head-raw-sha256 <RIGHT_EC319_HEAD_RAW_SHA> \
  --expected-genesis-raw-sha256 <EC319_GENESIS_SIGNED_RAW_SHA> \
  --registrar-id <FIFTH_REGISTRAR_ID> \
  --registrar-public-hex <FIFTH_PUB_64_HEX>
```

统一入口不接收 `attest`、`--out` 或私钥，严格使用固定 `python -I -B` 子进程，仅审计独立信任与真原件，不触碰 CAS/Host/Provider。

## 3. 保密、移机与进一步人工验收

- ZIP 仍有原签材料中老**绝对路径元信息**；本轮不改已签字节，线下传输前按组织策略加密分级。新 ACK claim 本身无未签本机文件路径。
- ACK 公钥身份绑定在明文 claim，**必须**在 ZIP/ACK 外面以受信方式取得 ID/公钥/挑战及整份 ACK SHA；单独 ACK + 自述公钥只能证明一把数学密钥签过某东西。
- 轻量定向本机 26 项通过（EC322 新 16 + EC321 继承 10），**EC317/318 深链在该 fixture 里 mock**。仍需真实原生产材料完整重放、真实第七组织授权、双设备线下复制、原 PS7/Windows/macOS/Provider/CI/真实 CAS/WORM 的统一验收。
- `exit=2` 是“真叉仍在”，绝不可把 ACK 用于伪造 fork resolution、globally latest、业务交付成功或产生业务侧状态机写入。
