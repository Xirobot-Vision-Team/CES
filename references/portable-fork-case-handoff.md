# EC321 离线分叉证据完整封存与接收端独立复核

## 前提与可验证事实

EC321 从 EC320 经原签复核的**真实同父签名分叉**收集证据，不从任意 CSV/旧 PASS 报告凭空生成。发送方已有：原 EC320 第六方签名 `witness-file`、两份 EC319 原 signed snapshot、两份本机只用于文件定位的 EC319 materials map、完整 EC317 二进制 ZIP、各次 EC318 三件原字节 signed receipt。并且已经**通过包外安全渠道独立保存**以下原始 pins 与 signer trust：

- `case-id`、`witness-id`、`witness-public-hex`、`witness-challenge-sha256`、`expected-witness-sha256`；
- `expected-left-sha256`、`expected-right-sha256`、左右各自 `expected-*-head-raw-sha256`；
- `expected-genesis-raw-sha256`、`registrar-id`、`registrar-public-hex`。

新 ZIP 的 `case-manifest.json` 自身不是签名材料，也不构成独立信任；签字者身份、公钥和全部 pin 都要由实际接收方**从其他受信渠道**独立设置。避免将发送方从同一个 ZIP 打印的 SHA 当成独立认证。

## 发送方命令

在私有 owner-only 0700 目录内执行（将示例参数替换为本机原**可信**真实值）：

```bash
python3 scripts/ces_cas_fork_case.py export \
  --out /private/transfer/case321.zip \
  --witness-file /private/evidence/sixth-witness.json \
  --left-file /private/evidence/left.json \
  --left-materials-file /private/evidence/left-map.json \
  --right-file /private/evidence/right.json \
  --right-materials-file /private/evidence/right-map.json \
  --case-id example_case --witness-id sixth_witness \
  --witness-public-hex <64-hex> --witness-challenge-sha256 <64-hex> \
  --expected-witness-sha256 <64-hex> \
  --expected-left-sha256 <64-hex> --expected-right-sha256 <64-hex> \
  --expected-left-head-raw-sha256 <64-hex> \
  --expected-right-head-raw-sha256 <64-hex> \
  --expected-genesis-raw-sha256 <64-hex> \
  --registrar-id fifth_registrar --registrar-public-hex <64-hex>
```

返回 `exit_code=2` 表示**完成真实分叉案卷创建且分叉仍需处理**，不表示正常唯一主链；检查 JSON `case_bundle_original_raw_sha256`，通过独立渠道固定后再交接文件。输出新建文件只允许 0600/O_EXCL/fsync，不允许覆盖。ZIP 包含原始签章数据；不包含原私钥，但原签材料中的旧路径可能仍敏感。不要明文上传公共渠道。

## 接收方命令

接收方无需源机原绝对路径、本机 EC319 unsigned materials map 或六方私钥，但**必须独立获取前述全部历史 trust pins 加上此次 ZIP 的整体 SHA**：

```bash
python3 scripts/ces_cas_fork_case.py verify \
  --bundle-file /private/inbox/case321.zip \
  --expected-bundle-sha256 <case-zip-original-raw-64-hex> \
  --case-id example_case --witness-id sixth_witness \
  --witness-public-hex <64-hex> --witness-challenge-sha256 <64-hex> \
  --expected-witness-sha256 <64-hex> \
  --expected-left-sha256 <64-hex> --expected-right-sha256 <64-hex> \
  --expected-left-head-raw-sha256 <64-hex> \
  --expected-right-head-raw-sha256 <64-hex> \
  --expected-genesis-raw-sha256 <64-hex> \
  --registrar-id fifth_registrar --registrar-public-hex <64-hex>
```

也可使用只读统一控制台，不允许 `export` 或 `--out`：

```bash
python3 scripts/ces_next.py audit-transfer-case DeliveryAudit VerifyPortableForkCase \
  --bundle-file /private/inbox/case321.zip \
  --expected-bundle-sha256 <case-zip-original-raw-64-hex> \
  --case-id example_case --witness-id sixth_witness \
  --witness-public-hex <64-hex> --witness-challenge-sha256 <64-hex> \
  --expected-witness-sha256 <64-hex> \
  --expected-left-sha256 <64-hex> --expected-right-sha256 <64-hex> \
  --expected-left-head-raw-sha256 <64-hex> \
  --expected-right-head-raw-sha256 <64-hex> \
  --expected-genesis-raw-sha256 <64-hex> \
  --registrar-id fifth_registrar --registrar-public-hex <64-hex>
```

**正式成功条件**：严格 ZIP 全 raw SHA+manifest+精确所需原 SHA 成员，私有临时路径生成与原始签章未被改变，`witness.verify` 真正重验左右每一个 EC319/318/317/316→294 全部历史，并再次确认同父五方真签分叉及六方 witness 真签。返回 `exit_code=2`，`status=independent_receiver_verified_unmodified_original_fork_after_pathless_import`。

**拒绝条件**包括：错误全 ZIP SHA、错误独立 signer/trust/head/genesis pin、身份或 challenge 重用、任何历史签章无效、EC318 的 offer/ack/closure 错 SHA/错顺序、缺 ZIP 原件、额外/压缩/遍历/重复成员、JSON 不规范、私有目录或权限不正确、资料超界、试图指派另一张 path-map 的来源文件。收到拒绝后需检查并重新获取独立原件，不能仅改 pins 让自称成功。

## 对接规则与统一验收积累

没有在本轮实现新的 receiver acceptance Ed25519；将接收组织独立真签可追溯 ACK 作为候选 EC322，不混入 EC321。一份经第六真签的 fork **并不证明**哪条分支正确、单一最新或全球防回滚。外部可信 CAS/WORM、组织身份与密钥授权和撤销、nonce 时间源、加密传输与物理到场证明需其他系统供给。本机 EC321 10 结构案例虽然真正执行了第五、第六密钥，原 EC317/318 full replay 在 fixture **mock**，从未冒称真实端到端验收；原 EC319 heavy fixture、真实不同设备、PowerShell7/15 Smoke、Windows/macOS/Provider/Inbox/Git/CI/E63–E66 均累积至最终用户联合验证。
