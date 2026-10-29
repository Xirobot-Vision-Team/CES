# EC274 操作协议：独立 HTTPS 双见证单调账本（Opt-in）

> 本指南仅用于部署及整合本轮新增的独立服务，不改变已运行的 EC273/272/PowerShell/Router。**实际异地独立托管、WORM 与证书吊销尚需生产侧独立验收。**

## 1. 角色和可信边界

- **Witness A/B/C（三个不同控制域）**：3 个 Ed25519 秘密 seed 各自只能由其持有人持有；对同一 canonical 提案的 `SHA256` 逐字节独立核验，且至少两个不同公钥签署。投票不能在业务 Host 或远端服务上生成。
- **Escrow authority（独立安全运营主机）**：运行 `daemon.py`，只持有本服务的**独立**签名 secret、公用的 3 witness 原始 Ed25519 公钥、公用独立 CA 和自己的 TLS 私钥/证书、独占的私有 JSONL 日志。公钥身份完整 SHA256 和首次 bootstrap 最小 seq/epoch 要预先审批、离线记录。
- **Operator / Protected Host（原业务主机）**：保存离线可信 CA bundle、精确 TLS leaf DER SHA256、独立 escrow 公钥原始 bytes/其 SHA256、3 个 witness 公钥原始 bytes/SHA256、事先审批的 `record SHA/index`、原 EC273 全部签章/证明文件。**不接收任一签章私钥**。只有收到经正确 pin 和新 nonce 验证的远端完整记录，且它**等于本地审批 head**时放行。

路径安全：运行账户必须为非 root Linux 用户，私钥、CA、公钥、proposal、签署票、日志均建议放在 owner 私有 `0700` 目录，安全文件 `0600`，不放在可被扫描的 Git 仓库或 audit root 内；此约束由多个源代码层实际执行。不要在外部可访问接口上直接暴露未加隔离的 TLS 私钥。远端持久存储需要独立备份/不可变介质/管理员证明；仅凭普通文件不可能声称跨主机物理不可回退。

## 2. 初始凭据和 SHA pin

准备 **四对**独立签名密钥（3 witness + 1 escrow，不可复用），已有 EC263 `generate_offline_keypair` 可生成私有 32 字节 seed 和独立 32 字节 raw public key。示意（在各安全机器的私有目录、使用 Python 环境已经具备 `cryptography` 时执行）：

```bash
python -c 'import sys;sys.path.insert(0,"construction");from offline_anchor_host.checkpoint import generate_offline_keypair;generate_offline_keypair("/private/escrow-ED25519.raw","/private/escrow-PUB.raw")'
sha256sum /private/escrow-PUB.raw
sha256sum /private/witness-A-PUB.raw /private/witness-B-PUB.raw /private/witness-C-PUB.raw
sha256sum /private/escrow-remote-ca.pem
openssl x509 -in /private/escrow-tls-leaf.pem -outform DER | sha256sum
```

上面 `/private` **仅作路径占位符**。生产由 PKI 颁发含确切主机名 SAN、合适 `serverAuth` 的有效 server TLS leaf，CA bundle 的完整字节 SHA 以及 leaf **DER** SHA 分别独立固定；不要把合成自签 CA 当成生产批准凭据。签名公钥必须为原始 32 字节，不能把 PEM、私钥或文本 sha256 串传入 `--escrow-public`。

## 3. 异地 escrow 守护程序（从 CES 根目录）

```bash
python construction/remote_escrow_host/daemon.py \
  --bind 192.0.2.10 --port 9443 \
  --namespace ces-project-alpha \
  --journal /private/ledger/remote-escrow.jsonl \
  --escrow-secret /private/escrow-ED25519.raw \
  --escrow-public-sha256 '<ESCROW_RAW_PUB_SHA256>' \
  --witness-public /private/witness-A-PUB.raw --witness-public-sha256 '<A_SHA256>' \
  --witness-public /private/witness-B-PUB.raw --witness-public-sha256 '<B_SHA256>' \
  --witness-public /private/witness-C-PUB.raw --witness-public-sha256 '<C_SHA256>' \
  --root-sha256 '<RECOVERED_ROOT_SHA256>' \
  --closure-sha256 '<EC270_CLOSURE_CERT_SHA256>' \
  --tls-cert /private/escrow-tls-leaf.pem \
  --tls-key /private/escrow-tls-key.pem \
  --bootstrap-minimum-sequence 1 \
  --bootstrap-minimum-epoch 1
```

示例 IP `192.0.2.10` 为**文档保留地址**，不是真实连接目标。生产请按审查通过的首记录最低序号/epoch 设定更严格的 bootstrap floors，而不是无条件复用 `1`。server CA / leaf 是 TLS 身份，不是 escrow Ed25519 在线响应的公钥。服务端**不接受** witness 私钥。端口应仅开放给已许可的操作员和 Host，并加网络边界限流/隔离。HTTP 协议只有：

- `POST /v1/read`：canonical JSON `{"namespace":"...","nonce":"32 lowercase hex"}`，返回由独立 escrow Ed25519 私钥签名的 nonce-bound `record`/`head_sha256`/`record_index`。
- `POST /v1/advance`：额外加 canonical `record`，仅当双方合法离线 witness vote + 单调 CAS 通过时执行 durable append + fsync，然后签名答复。不能跳号/覆盖、不能取代另一分叉、不能空头重置。

所有 JSON 必须按 `remote_escrow_host.escrow.canonical` 输出并以 `\n` 结尾。可重启程序保留原 journal；一旦日志不完整/不可信，禁止手动编辑、truncate、删除后重开，必须进行独立人工事件治理。单实例文件锁强制互斥；没有自动恢复/压缩。

## 4. 操作者完整签署/托管回读链路

以 `python construction/remote_escrow_host/operator.py <action> --help` 查看完整参数，EC273 继承了很多必须的 `--old-governance-*`、`--anchor-governance-*`、`--checkpoint-*`、`--freshness-chain-*`、`--tsa-*` 参数。**这些不是可以删掉的装饰选项**。

1. `inspect-remote`：提供 `--escrow-host`, `--escrow-port`, `--escrow-namespace`, `--escrow-tls-ca`, `--escrow-tls-ca-sha256`, `--escrow-tls-leaf-sha256`, `--escrow-public`, `--escrow-public-sha256`, 三组 `--freshness-witness-public[-sha256]`, `--root-sha256`, `--closure-sha256`, `--escrow-minimum-previous-index`。新 bootstrap 前期只可接受 `head_sha256 =` 64 个 `0`；新版本必须以带外记录的预期 `head` 为准。
2. `prepare-proposal`：继续携带上述远程参数、EC270/272 全量签章证明与 EC273 原始 TSQ/TSR/CA/叶证书/policy/时间地板，且给出 `--escrow-expected-previous-sha256`、`--escrow-minimum-previous-index`、`--output /private/proposal.json`。首先核验 EC272 全链和**当前** EC273 外部 TSA 签章，再从远端发起新随机 nonce 的签名 read；提案绑定该实际 head、上一最新收据 SHA、新一期全局 sequence、checkpoint 与治理 epoch、TSA 原文 hash，并预先核查单调策略。验证错误立即退出，没有远程提交。
3. 分别把 proposal **原始 bytes + 离线审核得到的 `proposal_sha256`**交给两个不同的见证持有人。他们分别执行 `sign-proposal --proposal ... --proposal-sha256 ... --witness-secret ... --witness-public-sha256 ... --output ...`。每人独立审核真实业务/签章证据、另一主机可信 pin 和请求时间，不能把离线批准做成在线空白授权。
4. `assemble-record --proposal ... --proposal-sha256 ... --vote <vote-A> --vote-sha256 ... --vote <vote-B> --vote-sha256 ... --escrow-namespace ... --root-sha256 ... --closure-sha256 ... --freshness-witness-public ... --freshness-witness-public-sha256 ... --output ...`：本地验证恰好两枚不同见证签名并组装完整记录，不改变远端账本。
5. `advance-remote`：提供所有远程/根/closure/witness pin，以及 `--escrow-expected-previous-sha256`、`--escrow-minimum-previous-index`、`--record`、`--record-sha256`；使用已认证 nonce read 先复核远端实际旧 head，CAS 提交，新 nonce 签名提交确认后**再发起第二个 nonce read**校验永久记录。成功结果回报 `escrow_record_sha256`，必须由独立渠道审批、固定给即将启动的 Host。若 `advance` 已落盘但网络断线，**不要盲目重试同一记录**；先 `inspect-remote` 审核当前头。

每个命令都在严格 pin 不匹配时失败关闭，不会接受只凭 URL/未钉住的在线 head 自动升级；单次合法推进使 previous 旧 head 失效，不存在后台自动升级。

## 5. 新的严格 Host（仍需完整继承 EC273 参数）

```bash
python construction/remote_escrow_host/serve.py verify-gate --help
python construction/remote_escrow_host/serve.py serve --help
```

所有原 EC273 必填参数、EC266 来源、EC265 保管、EC264 审计、EC272 当前签名 checkpoint/receipt、EC273 TSA 时间戳证明不能省略，并新增：

```text
--escrow-host                 DNS TLS 主机名（必须符合 leaf SAN）
--escrow-port                 1..65535
--escrow-namespace            operator 审批 namespace
--escrow-tls-ca               私有 CA bundle 文件
--escrow-tls-ca-sha256        CA bundle 完整原文 bytes SHA256
--escrow-tls-leaf-sha256      TLS leaf 证书 DER SHA256
--escrow-public               escrow Ed25519 独立 raw public key 文件
--escrow-public-sha256        上述 raw public bytes SHA256
--escrow-record-sha256        操作者预先审批的 EXACT 当前 head SHA256
--escrow-minimum-index        操作者预先审批的最小 record index（>=1）
```

继承的三个 `--freshness-witness-public`/`--freshness-witness-public-sha256` 仍要求完全相同名单；其它 EC273 参数的规则没有降低。远端签名 read **每次产生新随机 nonce** 并验证 CA、TLS SAN、TLS leaf、独立 escrow 公钥及双见证票、前驱/当前摘要。若远端返回了新 head 或旧 head 但与固定 `--escrow-record-sha256` 不符，Host **立即拒绝**，需独立操作员确认后以审批流程升级 pin；远端离线同样拒绝，不存在静默回退到 EC273 的逻辑。

## 6. 复测命令、真实边界与事故处理

```bash
runuser -u nobody -- /opt/pyvenv/bin/python3 -I -B construction/remote_escrow_host/test_escrow.py
runuser -u nobody -- /opt/pyvenv/bin/python3 -I -B construction/remote_escrow_host/test_host.py
runuser -u nobody -- /opt/pyvenv/bin/python3 -I -B construction/rfc3161_timestamp_host/test_timeproof.py
runuser -u nobody -- /opt/pyvenv/bin/python3 -I -B construction/rfc3161_timestamp_host/test_host.py
```

这四条是**本地研发证据**而非生产认可；`/opt/pyvenv/bin/python3`、Linux `runuser` 和 `/usr/bin/openssl` 是本地路径，不保证用户机器存在；可用匹配环境自行替换并汇报。预期 7+3+8+4=22 个各自独立用例。

最终联合验收还要组织真实不同设施的 Escrow 与 witness 密钥仪式，生产 SAN TLS、CRL/OCSP 与轮换、实际远端重启/断线/网络分区、异地持久备份或不可变存储恢复后的 hash/readback、真实可信 TSA、Podman/cgroup、系统源/CI/reviewer 以及原始 PowerShell/Router 的全部联合测试。不允许仅凭本轮普通 JSONL fsync 宣称物理不可回退、真实分布式见证、整体 Quality PASS 或已完成 EC250 冻结。
