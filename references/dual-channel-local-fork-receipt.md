# EC324 离线两渠道原 SHA 接收登记 — 操作手册

## 目的与不可跳过的信任前提

本协议只**真实执行**本地收件核验、原签全链重演与有界不可覆盖快照，不会建立受信机构、独立物理信道、全球 CAS/latest、WORM 或解决真分叉。输入的 EC323 ZIP 本身以及 ZIP 内自述的 SHA、签名人 ID 与信任 pin 均**不能**当独立信任源。

签收准备由 `origin`、`recipient` 两位拟定操作者在**实际分离的环境**中分别决定：相同 handoff ID、registry ID、预期接收序号、前一已受信的登记整份 SHA；双方必须通过各自**不同的包外可信通道**核实封装 whole SHA、EC321 原案卷 ZIP whole SHA、EC322 原 ACK whole SHA、EC321 全 12 原 history pins 和第七签 ID、公钥/挑战、ACK ID。两个角色的 `operator_id` 只是协议中的可比较字符串，不是签名、身份鉴权、现实机构授权证明。

- 原 `EC323` capsule 必须由旧 `seal` 真验原链生成，且外部冻结**whole raw** ZIP SHA（不是 manifest 内 SHA）；原 EC321 ZIP 与 EC322 ACK 分别按**原文件原字节**而非展示 JSON 指纹冻结 SHA。
- `origin` 与 `recipient` 在各自设备上运行 `prepare-channel` 生成两个不同的、**无签名**的 JSON pin 文件。各自通过独立受信渠道交付其文件以及**本文件完整原字节 SHA**，接收方自己记录并核对两枚不同 SHA。
- 对于追加，两个操作者必须先通过受信外部渠道确认前一版 `registry_snapshot_original_raw_sha256` 和当前整数序号。绝不可仅从新 ZIP、两份 pin 文档、后继未签快照里自行抄取这个已受信头。

## 初始化独立目录与必要参数

在具备 POSIX 私有目录模式的平台上，以**当前所有者**创建源/收件各自 `0700` 的本地工作目录（目录不得通过符号链接访问）：

```sh
mkdir -p /private/ces-handoff-origin /private/ces-handoff-recipient
chmod 700 /private/ces-handoff-origin /private/ces-handoff-recipient
```

以下示例的 `...` 是占位符；须逐项替换真实受信外部值，不能直接运行。所有路径须为**规范、绝对**文件名；输入文件需是 0600、唯一硬链接、当前所有者常规文件且父目录为 0700。唯一脚本入口是：

```text
python3 -I -B scripts/ces_cas_fork_receipt.py prepare-channel
python3 -I -B scripts/ces_cas_fork_receipt.py receive
python3 -I -B scripts/ces_cas_fork_receipt.py verify
```

`prepare-channel` 的**共同必需参数**（两人在各自环境中重复，只有角色/操作者 ID / 输出路径不同）：

```text
--channel-role origin|recipient
--operator-id <two-distinct-ids>
--handoff-id <same-handoff-id>
--registry-id <same-local-registry-id>
--expected-sequence 1
--expected-prior-registry-raw-sha256 0000000000000000000000000000000000000000000000000000000000000000
--expected-capsule-sha256 <external-whole-EC323-ZIP-SHA>
--expected-bundle-sha256 <external-whole-EC321-original-ZIP-SHA>
--expected-ack-sha256 <external-whole-EC322-original-ACK-SHA>
--case-id ... --witness-id ... --witness-public-hex ...
--witness-challenge-sha256 ... --expected-witness-sha256 ...
--expected-left-sha256 ... --expected-right-sha256 ...
--expected-left-head-raw-sha256 ... --expected-right-head-raw-sha256 ...
--expected-genesis-raw-sha256 ... --registrar-id ... --registrar-public-hex ...
--ack-id ... --seventh-receiver-id ... --seventh-receiver-public-hex ...
--seventh-receiver-challenge-sha256 ...
--out <new-private-file>.json
```

请从 `scripts/ces_cas_fork_receipt.py prepare-channel --help` 获取机器实际选项拼写。两个文档须分别获取外部整 SHA，并且保证每份文件未被重新序列化、没有多余空白、没有转义后复制改写。此命令 `exit=0` **只表示未签 pin 文档生成**，不表示实际签收；生成两个文件不能自动证明两独立 channel。

## 接收：仅在真实旧签名复核后写本地不可覆盖头

在收件方设备上提供**独立记录的**两份 pin 文件整 SHA；第一次 `prior_registry_file` 必须省略，使用明确全零前序 SHA：

```sh
python3 -I -B scripts/ces_cas_fork_receipt.py receive \
  --capsule-file /private/ces-handoff-recipient/originals-capsule.zip \
  --origin-file /private/ces-handoff-recipient/independent-origin-pins.json \
  --expected-origin-sha256 <OUTSIDE-CHANNEL-1-FILE-WHOLE-SHA> \
  --recipient-file /private/ces-handoff-recipient/independent-recipient-pins.json \
  --expected-recipient-sha256 <OUTSIDE-CHANNEL-2-FILE-WHOLE-SHA> \
  --registry-id receiving_registry --expected-sequence 1 \
  --expected-prior-registry-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  --out /private/ces-handoff-recipient/receipt-snapshot-001.json
```

将输出 `registry_snapshot_original_raw_sha256` **立即通过独立可信渠道**冻结、与原始快照文件的整 SHA 共同保存，作为下一轮唯一准许引用的外部头。成功真分叉应返回 **exit 2** 和 `local_offline_dual_channel_fork_receipt_recorded_no_external_cas`；这不是命令失败，也**不是全局成功或唯一分支**。实际接收端用户负责保护原文件与外部 SHA；没有真正外部存证时，不能宣称抗全部回滚。

## 追加：有界 2–16 条原字节累积快照

下一份案卷必须有不同的 `handoff_id` 和不同 EC323 原封装 SHA（禁止同一封装重复消费）；双方重新制作 `origin`/`recipient` 未签 pin 文件，且都独立固定**上一版登记整原 SHA**与 `expected_sequence 2`。将新的两个 pin 文件的 whole SHA 通过各自渠道外存，收件方调用：

```sh
python3 -I -B scripts/ces_cas_fork_receipt.py receive \
  --capsule-file /private/ces-handoff-recipient/new-capsule.zip \
  --origin-file /private/ces-handoff-recipient/second-origin-pins.json \
  --expected-origin-sha256 <NEW-OUTSIDE-ORIGIN-SHA> \
  --recipient-file /private/ces-handoff-recipient/second-recipient-pins.json \
  --expected-recipient-sha256 <NEW-OUTSIDE-RECIPIENT-SHA> \
  --registry-id receiving_registry --expected-sequence 2 \
  --expected-prior-registry-sha256 <EXTERNALLY-FROZEN-OLD-SNAPSHOT-WHOLE-SHA> \
  --prior-registry-file /private/ces-handoff-recipient/receipt-snapshot-001.json \
  --out /private/ces-handoff-recipient/receipt-snapshot-002.json
```

它不会更新 `receipt-snapshot-001.json`，而是重读旧头原字节 + 验证所有前缀快照 SHA 链，再重放**当前** EC323 案卷所有真签，最后生成一个全新 owner-private 0600 / O_EXCL / fsync 累积快照。不能靠一个本地新文件排除并发 sibling 同父写：这需要独立线性化的外部头服务/运营控制，仍留给真实部署与最终验收。

## 复验已收到的最后一笔原件

`verify` **不能**签名、准备 pin、接收或创建新的外部登记。它要求有当前快照 whole SHA、两个渠道文件各自 whole SHA、收件人已冻结的预期序号和前头 SHA；`capsule-file` 仍必须存在，不能仅凭以前的 `verified` 布尔字段通过：

```sh
python3 -I -B scripts/ces_cas_fork_receipt.py verify \
  --registry-file /private/ces-handoff-recipient/receipt-snapshot-002.json \
  --expected-registry-sha256 <EXTERNALLY-FROZEN-CURRENT-SNAPSHOT-WHOLE-SHA> \
  --capsule-file /private/ces-handoff-recipient/new-capsule.zip \
  --origin-file /private/ces-handoff-recipient/second-origin-pins.json \
  --expected-origin-sha256 <NEW-OUTSIDE-ORIGIN-SHA> \
  --recipient-file /private/ces-handoff-recipient/second-recipient-pins.json \
  --expected-recipient-sha256 <NEW-OUTSIDE-RECIPIENT-SHA> \
  --registry-id receiving_registry --expected-sequence 2 \
  --expected-prior-registry-sha256 <EXTERNALLY-FROZEN-OLD-SNAPSHOT-WHOLE-SHA>
```

统一 Console **只读 `verify`，且严格隔离子进程，不传出写入能力**：

```text
python3 -I -B scripts/ces_next.py audit-fork-receipt DeliveryAudit VerifyDualChannelLocalForkReceipt \
    [以上 verify 的全部参数]
```

`verify` 返回 `exit 2` 是因为重验的旧证据本身确实**真签分叉尚未解决**。`exit 3/4/5` 为权限、输入或环境失败，**不得**将 failure 当作已签收。旧纪录的原 EC323 ZIP 未随最新快照嵌入，复核它们真实签名仍须提供对应旧原 ZIP + 两份旧渠道文档并单独运行历史版本的验签；快照链只承诺它们记录的 SHA 结构链接。

## 最后统一验证清单（本轮不冒称完成）

在最后收口验收时提供两台真实物理设备、两个可信的独立收/发身份与渠道、外部完整 SHA 冻结/持久存证、全 EC294→EC324 无 mock 真历史原件、组织签名权利与撤销验证、并发后继 CAS/WORM 原子登记、系统断电恢复/Windows/macOS 权限、原 PowerShell7 Smoke15、真实 Provider/Inbox/Git/CI/E63–E66 与其他业务验收。EC249 incomplete / EC250 BLOCKED / B001 OPEN / global Quality PASS=false / final NOT_STARTED 不变。
