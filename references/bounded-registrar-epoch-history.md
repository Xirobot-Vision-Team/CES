# EC306 — 有界多代 registrar 历史：原 EC305 治理证书 + 原 EC304 已签账本

**完整施工包：V6.16 / R306 / EC306。** 本文件是实施和人工接管协议，不是第三方组织治理背书。EC306 不更改 EC304 的签名记录格式，不签发新的自创治理票，也不改变 EC305 的 planned 三签 / emergency_compromised 新登记员+governor 双签域。所有新 registrar 签章仍来自原 EC304；所有密钥切换证书仍来自**原 EC305**。

## 信任模型与硬约束

- 最多 **8 个 epoch**，每代最多 **256 条** EC304 签名 ACK/challenge 登记。前 `N-1` 代账本冻结，最后一代是 active，可暂为 `(GENESIS, 0)`，仅当先前一代含至少一条已签记录时允许换钥。初始代必须由已存在的、**独立 raw SHA+序号**钉住的非空原 EC304 账本启动。
- `ces.ec306.registrar_epoch_chain.v1` 是路径无关、规范 JSON、尾随单一换行的**索引**，包含固定 registry ID、独立预先受信 governor 公钥、首位 registrar 公钥、前个索引原字节 SHA 和每代（公钥、完整账本 raw SHA、严格序号、旧转新 EC305 证书 raw SHA、换钥 nonce/治理决议 SHA、cutover mode）。索引本身**没有新的签名**：必须从可信包外保管独立取得它的**完整原字节 SHA**，而不能把本地索引文件的 SHA 当作最新权威。
- 所有 `verify-history`、`verify-latest`、`rotate`、`register` 和 `commit` 都要求八个包外信任字段：`registry_id`、`governor_public_hex`、`initial_registrar_public_hex`、`chain_raw_sha256`、`epoch_count`、`active_registrar_public_hex`、`active_ledger_raw_sha256`、`active_ledger_sequence`。每个非空 epoch 对应一个按序重复的 `--epoch-ledger-file`，每张换钥证书对应一个按序重复的 `--cutover-certificate-file`，**不能缺文件、重排或合并成只取最新一代**。
- 验证时重新读取各份 0600/owner/single-link 私有文件、检查外部锁定的完整 raw SHA、严格 JSON 格式和全部原 EC304 签名/前驱签名哈希；用前一代账本的实际 raw SHA、序号，按原 EC305 `_check_certificate` 验原签名证书及独立治理角色。必须保证历代 registrar 公钥唯一、全程 governor 公钥固定、所有已见登记员和 governor 公钥均不与任一 epoch 的 A/B witness/receiver 公钥重用；跨 **全部 epoch** 按完整记录 SHA 挑战/ACK 拒绝重复。旧原 ZIP/ACK 不保存在历史索引，旧物理证据**不是逐件重放**。
- 注册前先完整验证全部旧签章/证书/角色，再拒绝任何旧 challenge、旧 ACK，调用**原封未改** EC304 `register` 对最新原 EC303 ZIP/ACK→EC294 完成真实签名重演并写入**候选账本**。`commit` 再次核验所有历史、候选签名、恰好新增一条记录及其完整旧账本 raw SHA 前驱、最新原 EC303 签收真重演后，才以 0600、`O_EXCL`、fsync 写**下一份索引**。候选和索引的两个文件不是原子事务，崩溃/竞争时不能自动当成权威最新；交由独立 CAS/WORM 审批采用哪条分支。

## 推荐离线流程

先设置 `umask 077`，在受控 0700 私有目录保留所有不可改写旧账本/证书和每次索引。所有示例均在工程根目录运行。尖括号代表用户**从独立保管系统抄取的真实值**，不是文件自产生的证明。

1. **首次索引**：以既有原 EC304 根账本为起点：

   ```sh
   python3 scripts/ces_registrar_epochs.py start \
     --expected-registry-id '<registry_id>' \
     --expected-governor-public-hex '<trusted_governor_64hex>' \
     --expected-initial-registrar-public-hex '<root_registrar_64hex>' \
     --initial-ledger-file /private/ledger-0.json \
     --expected-initial-ledger-sha256 '<independently_pinned_full_file_sha256>' \
     --expected-initial-sequence 2 --out /private/chain-0.json
   ```

   `start` 只接纳已完成 EC304 完整签名验证的非空根账本。之后将程序返回的 `chain_raw_sha256` 与 epoch count、active 公钥、ledger raw SHA/seq **独立登记**，才可进入下一步。首次索引的前驱 SHA 是 `(GENESIS)`。

2. **每次换钥**：先使用原 `scripts/ces_registrar_rollover.py prepare / sign / assemble`，分别在对应密钥保管端执行，获得针对**索引中当前 active 账本最新完整 SHA/seq**的原 EC305 证书；旧 registrar 已泄露时用 `emergency_compromised`，且**不交旧钥签字**。不能只凭新密钥签章或 EC305 intent 自称已有证书。然后用 EC306 `rotate`：

   ```sh
   python3 scripts/ces_registrar_epochs.py rotate \
     --chain-file /private/chain-0.json \
     --expected-chain-raw-sha256 '<externally_pinned_chain_sha>' \
     --expected-registry-id '<registry_id>' \
     --expected-governor-public-hex '<governor_pub>' \
     --expected-initial-registrar-public-hex '<root_pub>' \
     --expected-epoch-count 1 \
     --expected-active-registrar-public-hex '<old_registrar_pub>' \
     --expected-active-ledger-raw-sha256 '<old_active_ledger_sha>' \
     --expected-active-ledger-sequence 2 \
     --epoch-ledger-file /private/ledger-0.json \
     --new-certificate-file /private/cutover-0-1.json \
     --expected-new-certificate-sha256 '<independently_pinned_certificate_sha>' \
     --expected-new-registrar-public-hex '<new_pub>' \
     --expected-cutover-nonce-sha256 '<external_nonce_sha>' \
     --expected-governance-decision-sha256 '<external_decision_sha>' \
     --cutover-mode planned --out /private/chain-1.json
   ```

   此索引新增空 active epoch；**不能**在未写入新 ACK 前运行 `verify-latest` 声称已有接收证明，此时可运行 `verify-history`。到下一次换钥时，`--epoch-ledger-file` 应按根→最新顺序给出**所有非空**代账本，`--cutover-certificate-file` 按第一次→最新的顺序补齐**之前所有**治理证书；新证书单独交给 `--new-certificate-file`。旧 governor 固定，若需 governor 自身换钥要另立协议，不得更改历史锚点。

3. **登记候选而非提交**：每次以**最新被外部认可**的索引调用 `register`，传入全部非空 epoch ledger 文件及历史证书、公钥/最新 tip 等八个包外字段，并添加本次 EC303 `--bundle-file`、`--expected-bundle-sha256`、`--acknowledgement-file`、`--expected-acknowledgement-sha256`、源/接收方 ID、接收者公钥、challenge SHA、EC302 四 tip 和 A/B 公钥/ID 八 pin，以及仅独立 CLI 接受的 `--active-private-key-file /private/key.raw32 --out /private/next-ledger.json`。函数返回真实已签 `ledger_raw_sha256`、sequence，但是 `candidate_committed_to_chain=false`。**不要用原 EC304 或仅 EC305 一步包装器绕开全历史检查。**

4. **重核后提出新索引**：用**同一旧索引**和全部旧 epoch 文件调用 `commit`，增加 `--candidate-ledger-file`、`--expected-candidate-ledger-sha256`、`--expected-candidate-sequence`、同一份最新真实 ZIP/ACK 和 pin，以及 `--out /private/next-chain.json`。候选必须是旧 active 原始账本**恰好追加一条**。返回下一份索引完整 raw SHA。独立保管者检查预期旧索引 SHA 未被另一候选抢占，再原子持久地发布新 SHA+epoch_count+active key+ledger sha+seq；未取得外部确认时不可对外声称为最新。

5. **只读审核**：`verify-history` 适用于刚换钥还未写新 ACK 的 active 空账本；`verify-latest` 必须有非空 active 账本，并额外带**全部最新** EC303 ZIP/ACK 和八 pin，真正调用原 EC304 `verify` 复验最新原 EC303→EC294。统一控制台仅提供：

   ```text
   python3 scripts/ces_next.py audit-epochs DeliveryAudit VerifyRegistrarEpochs \
     --chain-file /private/next-chain.json \
     --expected-chain-raw-sha256 <external_sha> ... \
     --epoch-ledger-file /private/ledger-0.json \
     --epoch-ledger-file /private/ledger-1.json \
     --cutover-certificate-file /private/cutover-0-1.json \
     ... <independent latest EC303 evidence flags>
   ```

   控制台严格固定隔离子进程调用 `verify-latest`，不接受私钥、`rotate`、`register` 或 `commit`；原统一 Router 74 路由及 11 条 `HOST_REQUIRED` 默认拒绝未修改。原 PowerShell CLI 仍 V4.60/R150。

## 错误语义及必须由用户统一验证的内容

- 独立 CLI 正常为 0；`permission_denied` 3、`invalid_input` 4、`unavailable` 5。独占写失败、历史证书缺失、任何哈希/序号不符、签名错、跨 epoch 重播、任何历史 registrar 密钥或 governor 角色复用、未完成旧 epoch 都拒绝，拒绝后不会宣称业务写入。索引只绑定原始字节和签章；`previous_chain_raw_sha256` 是候选来源指针，**本工具不自动读全套过去版本的索引快照作外部 CAS 证明**。
- **强制包外动作**：先独立授权 governor 和密钥职责/撤销；对旧 registrar 的组织级外部撤销发布；可信 nonce/challenge 唯一发行；外部 latest index SHA/epoch_count/ledger pin 的原子 CAS/WORM；恶意 fork 取证与选择；候选签完而新索引没写成时的人工恢复；历史旧 ZIP/ACK 的单独持久封存；跨两机、共享盘、NFS、目录 race、加密介质、掉电、可信时间及生产 Provider/Inbox；原生 PS7 Smoke15、跨 OS、Git/CI/E63–E66、EC249/EC250/B001 和最终用户联合验收。
- EC306 聚焦用例在本机继承 **原 EC294→EC305 真实签名 fixture**，并模拟三代（planned 与 emergency_compromised 两次切换），不是实际独立人、多台机器、可信外部保管或正式生产验收。本轮只施工 EC306，不提前实施 EC307。
