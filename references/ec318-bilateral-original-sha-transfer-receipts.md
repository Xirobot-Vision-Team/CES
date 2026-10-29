# EC318 — 完整旧 Ed25519 原签名 ZIP 的离线双向移交（操作协议）

## 参与者、输入与强制包外锚

参与者：原两位 EC316 custodian A/B（旧签证书内身份）、**新**发送方 Sender（本地签两次）、**新**接收方 Receiver（接收后签一次）、可选只读核验员。四种 ID 和 Ed25519 公钥不能重复。EC317 原始 ZIP 不在 ZIP 内带有可信的 *自身* 完整 SHA，必须独立交付、独立冻结。**发送前**双方分别钉住：源路径文字 `--chain-file`, `--ledger-manifest-file`（接收方不需该物理路径存在）、原 chain/ledger/latest cert/latest challenge 四个原 SHA、两位 custodian ID/公钥、原完整 ZIP SHA、Sender/Receiver ID/公钥、发送方 challenge SHA 和收方 challenge SHA。最后回执确认时另外独立生成/冻结第四份 final confirmation challenge SHA；不能与旧证书、sender 或 receiver 的 challenge 重复。

所有输入文件必须是 owner-private 父目录下的 0600、正则、单硬链接文件，禁止符号链接及非规范/相对路径。要约、ACK、最终签认需要不同的**新**目标文件，各有自己的完整原字节 SHA，不是内部字段 canonical SHA；收件方不需要也不应信任任意以前的 `PASS` 摘要。两个新私钥分别保存为 32 字节原生 Ed25519 seed，0600 存储，只放到各自物理保管域；**不要把私钥放进 ZIP、聊天附件、代码仓库或命令输出**。

## 四阶段 CLI

下方 `COMMON` 为经双方独立填写、冻结的公共实参集合；不要原样执行占位符。仅 `--bundle-file` 是各设备上**本地**实际 ZIP 存储位置，可以不同；旧 `--chain-file` 等作为签名原件路径文字，必须两边完全一致，不应改写路径字串。

```bash
COMMON=(
  --bundle-file /private-receiver/original-ces-evidence.zip
  --expected-bundle-sha256 '<complete-independent-ZIP-raw-SHA256>'
  --chain-file /old-source/path/EC316-chain.json
  --expected-chain-sha256 '<original-chain-raw-SHA256>'
  --ledger-manifest-file /old-source/path/EC315-ledger.json
  --expected-ledger-manifest-sha256 '<original-ledger-raw-SHA256>'
  --expected-latest-certificate-sha256 '<original-latest-certificate-raw-SHA256>'
  --expected-latest-challenge-sha256 '<original-old-certificate-challenge-SHA256>'
  --custodian-a-id '<old-custodian-A-id>'
  --custodian-a-public-hex '<old-custodian-A-ed25519-pub-hex>'
  --custodian-b-id '<old-custodian-B-id>'
  --custodian-b-public-hex '<old-custodian-B-ed25519-pub-hex>'
  --sender-id '<separately-authorized-sender-id>'
  --sender-public-hex '<new-sender-ed25519-pub-hex>'
  --receiver-id '<separately-authorized-receiver-id>'
  --receiver-public-hex '<new-receiver-ed25519-pub-hex>'
  --sender-exchange-challenge-sha256 '<independent-sender-challenge-SHA256>'
  --receiver-exchange-challenge-sha256 '<independent-receiver-challenge-SHA256>'
)

# 1. 发送方在独立 full EC317 replay 成功后签署要约。
python3 scripts/ces_cas_transfer.py sender-offer "${COMMON[@]}" \
  --private-key-file /sender-private/ed25519.bin \
  --out /sender-private/transfer-offer.json
# 安全通道转送完整 offer 文件及包外 offer RAW SHA。

# 2. 收方在其本地 ZIP 原件全验、发送方真实签名确认后签 ACK。
python3 scripts/ces_cas_transfer.py receiver-ack "${COMMON[@]}" \
  --offer-file /receiver-private/transfer-offer.json \
  --expected-offer-sha256 '<external-offer-raw-SHA256>' \
  --private-key-file /receiver-private/ed25519.bin \
  --out /receiver-private/transfer-ack.json
# 安全通道回送完整 ACK 文件及包外 ACK RAW SHA。

# 3. 发送方重新核验所有原件和接收方签章，最后才签最终确认。
python3 scripts/ces_cas_transfer.py sender-confirm "${COMMON[@]}" \
  --offer-file /sender-private/transfer-offer.json \
  --expected-offer-sha256 '<external-offer-raw-SHA256>' \
  --ack-file /sender-private/transfer-ack.json \
  --expected-ack-sha256 '<external-ack-raw-SHA256>' \
  --sender-confirmation-challenge-sha256 '<fresh-external-final-challenge-SHA256>' \
  --private-key-file /sender-private/ed25519.bin \
  --out /sender-private/transfer-closure.json

# 4. 双方或第三方重新核验所有原件和三份真签，verify 不需要私钥。
python3 scripts/ces_cas_transfer.py verify "${COMMON[@]}" \
  --offer-file /receiver-private/transfer-offer.json \
  --expected-offer-sha256 '<external-offer-raw-SHA256>' \
  --ack-file /receiver-private/transfer-ack.json \
  --expected-ack-sha256 '<external-ack-raw-SHA256>' \
  --sender-confirmation-challenge-sha256 '<fresh-external-final-challenge-SHA256>' \
  --closure-file /receiver-private/transfer-closure.json \
  --expected-closure-sha256 '<external-closure-raw-SHA256>'
```

上述路径仅为结构示意，发送与收方应在自己的隔离域中调整 `COMMON --bundle-file` 和新签名文件位置。旧原始 source 绝对路径只作为不改写的 SHA-签名来源引用。每轮签字前需要从独立可信来源获得相同的原 pins，而不是从收到的 ZIP/offer/ACK/closure 或控制台自动推导。

**统一控制台**用 `python3 scripts/ces_next.py audit-transfer DeliveryAudit VerifyBilateralTransferReceipt` 加上述 verify 的所有公开只读参数；该入口拒绝所有其他 Action/Mode、私钥、`--out`、签字命令，也不改变 EC241/243 已有 74 条路由、Host 11 条拒绝。

## 检验重点与真实能力边界

- 先凭独立完整 ZIP raw SHA 验证 archive 封套和原 EC317 原路径无兜底快照，再重跑 EC316/315→294 原 Ed25519 历史；签字前不得只消费旧一次的报告。
- 三段 Ed25519 严格分域；要约绑定两个 transfer challenge 和四个旧证据 pins，ACK 真签绑定精确 sender offer 原 SHA + 旧历史 replay 原投影 SHA，最终签章又绑定精确 ACK/offer 原 SHA + 第四份 challenge。
- 新文件的 full SHA 用 `sha256sum` 对**整个**已签 JSON 文件计算，包含末尾一个 LF；`binding_canonical_sha256` 仅为没有 LF 的规范 JSON 内部承诺，不可当作文件 SHA 替用。
- 严格拒绝带多余字段、重复字段、非规范 LF 编码、签章伪造、对旧证书/ZIP 单独重新哈希后冒充旧可信 pin、新 signer 公钥重用、4 challenge 重用、原绝对路径修改、ACK 交换、旧包原件漏读、覆盖既有文件。
- **只证明**特定公钥对特定有限已重演来源出具的三份密码学声明。实际不同设备、真人签章权限、证书吊销、challenge 真不可预知/全局未用、真实外部 WORM/单调 CAS 或全局 latest、真实 Provider/Inbox 交付与终验，均未证明；另需组织现实审计。绝不要将本地 signed ACK 当成邮件送达/商业审批或数据可靠存储的证明。
