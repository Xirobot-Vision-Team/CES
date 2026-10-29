# EC304 操作：已签收据的独立一次性挑战登记与外部防回滚检查点

**V6.14 / R304 / EC304；仅离线软件功能。** 本轮补上 EC303 的**跨次签收 challenge 重复使用检查**。不是自动化的可信挑战发行器，也不是分布式共识或不可回滚数据库。任何声称“全网没有别的登记”都需要另外可信、单调递增的外部登记治理。

## 1. 前提与四方独立公钥

以 EC302 与 EC303 已生成并经独立保管 SHA 的 **完整 ZIP、完整接收回执 ACK、8 个 witness/session/receipt 原始 pin、源 ID、接收 ID、本次 challenge SHA 和接收方公钥**为输入。接收回执本身必须已有 EC303 真实私有导入/重验后的独立第三方 Ed25519 签名；EC304 会实际重验这个回执、ZIP 和原 EC301→EC294 全签名历史。登记员需要**第四把新的 Ed25519 密钥**，其公钥与 A/B 两见证、接收方全部不相同，且由使用者通过**包外可信渠道**独立确认。仅把不同的公钥字节写在命令行不证明四个不同的人/设备，也不能取代生产 HSM 或钥匙撤销管理。

在私有 POSIX `0700` 目录外部配置 `registrar-ed25519.key`：内容严格为 32 字节的原始 Ed25519 私钥，单链接普通文件、`0600`，不是 PEM。**绝不**把私钥打进 EC302 证据 ZIP、EC303 回执或 EC304 登记账本。登记输出也必须位于已有的、所有者私有的 `0700` 目录，操作员只允许**创建新的、不覆盖**的文件。

以下变量必须由操作员**独立供应**，不得从所接收 ZIP、ACK 或待验证登记账本回填作为可信锚点：

```bash
COMMON=(
  --expected-a-id "$A_ID" --expected-a-public-hex "$A_PUB" --expected-a-tip "$A_TIP"
  --expected-b-id "$B_ID" --expected-b-public-hex "$B_PUB" --expected-b-tip "$B_TIP"
  --expected-session-tip "$SESSION_TIP" --expected-receipt-tip "$RECEIPT_TIP"
)
ACK_ARGUMENTS=(
  --bundle-file "$ZIP" --expected-bundle-sha256 "$ZIP_SHA"
  --acknowledgement-file "$ACK" --expected-acknowledgement-sha256 "$ACK_SHA"
  --expected-sender-id "$SENDER_ID" --expected-receiver-id "$RECEIVER_ID"
  --expected-receiver-public-hex "$RECEIVER_PUB"
  --expected-exchange-challenge-sha256 "$CHALLENGE_SHA"
  --expected-registry-id "$REGISTRY_ID"
  --expected-registrar-public-hex "$REGISTRAR_PUB"
)
```

`ZIP_SHA` 是完整 ZIP *raw bytes* 的 SHA256，`ACK_SHA` 是包括尾部 LF 的完整已签回执 raw SHA256，`CHALLENGE_SHA` 必须与 EC303 正式签收时使用的相同。`REGISTRY_ID` 是约定好的独立固定登记域标识，`REGISTRAR_PUB` 是单独验证过的登记员公钥。四个原始 latest tip 来自各自外部保管；任何一个被本机文件擅自替代都失去信任模型。

## 2. 首条登记：仅有外部确认“空历史”才允许 GENESIS

第一次登记必须明确传入**64 个零**的 genesis 前驱 SHA 和外部预期序号 `0`，不提供 `--previous-ledger-file`。这只是一份**请求外部保管方授权初始化**的约定，不证明在其他机器或其他 registry ID 下绝无已有签收；外部登记方必须确保同一登记域只有一个可信的起点。

```bash
python3 scripts/ces_challenge_registry.py register \
  "${COMMON[@]}" "${ACK_ARGUMENTS[@]}" \
  --expected-previous-ledger-sha256 "$(printf '0%.0s' {1..64})" \
  --expected-previous-sequence 0 \
  --registrar-private-key-file "$REGISTRAR_KEY" \
  --out "$PRIVATE/registry-000001.json"
```

成功结果 `sequence: 1`、`ledger_raw_sha256` 是完整最新登记文件的 SHA（包括换行），不是单条记录的摘要。**立即通过外部、独立、不可回滚的保管机制**同时保存 registry ID、登记员公钥、完整 raw SHA 和序号；由外部系统确认这次从 `(GENESIS,0)` 到 `(SHA,1)` 的 compare-and-swap 被唯一接受。此代码既不能执行该 CAS，也不能因为 `0` 自动宣称“已登记为全局最新”。

## 3. 后续登记：每次仅接受包外指定的完整前驱快照

先从独立可信保管方读取**经其确认最新**的 `(PREV_SHA, PREV_SEQ, REGISTRY_ID, REGISTRAR_PUB)`，取得这份完整的、私有的前驱登记文件。先为新的交接获得**新的** challenge SHA、完整 EC303 新 ACK 与其独立 raw SHA，然后运行：

```bash
python3 scripts/ces_challenge_registry.py register \
  "${COMMON[@]}" "${ACK_ARGUMENTS[@]}" \
  --previous-ledger-file "$PRIVATE/registry-000001.json" \
  --expected-previous-ledger-sha256 "$PREV_SHA" \
  --expected-previous-sequence "$PREV_SEQ" \
  --registrar-private-key-file "$REGISTRAR_KEY" \
  --out "$PRIVATE/registry-000002.json"
```

新签发前代码会检查**完整历史全部登记员签名、先前每一份完整前驱文件 SHA、严格连续序号和单条前驱签名记录 SHA**，并检查所有已有条目中不存在本次 `CHALLENGE_SHA` 或 `ACK_SHA`；即使双方 ID 不同也拒绝同域重复挑战。之后调用原 EC303 `verify_ack` **重新验接收方 Ed25519 签名与完整 EC302→EC294 原签名证据**，成功才读取第四把签名私钥、对“此次校验过的签收 + 前驱 SHA”域分离签名。所有新文件 O_EXCL / 0600 / fsync 文件及父目录，绝不覆盖前一轮。

**重要：外部 CAS 决议不在此程序内。** 若两次离线运行都基于同一份经外部确认的前驱，可能产生两个分别有效的、不同的后继签名快照（fork）。外部保管人只能将其中一个声明为其正式最新记录，必须单独保存分叉证据与处理决定；不能默默丢弃冲突并把另一个本地文件称为全局最新。没有外部可信前驱，局部防重放只能针对**已提供的历史前缀**生效。

## 4. 只读验：完整登记签名历史 + 最新完整原始证据

对最新提供的登记快照，必须从外部通道独立取得完整 `LATEST_SHA`、`LATEST_SEQ`、登记域和公钥、最新 ACK/ZIP 全部旧 pin。以下两个入口都不改原业务，统一控制台**只允许 verify，不允许 register 或传入私钥**：

```bash
python3 scripts/ces_challenge_registry.py verify \
  "${COMMON[@]}" "${ACK_ARGUMENTS[@]}" \
  --ledger-file "$LATEST_LEDGER" \
  --expected-ledger-sha256 "$LATEST_SHA" \
  --expected-sequence "$LATEST_SEQ"

python3 scripts/ces_next.py audit-registry DeliveryAudit VerifyChallengeRegistry \
  "${COMMON[@]}" "${ACK_ARGUMENTS[@]}" \
  --ledger-file "$LATEST_LEDGER" \
  --expected-ledger-sha256 "$LATEST_SHA" \
  --expected-sequence "$LATEST_SEQ"
```

验证逐条验全部历史登记员签章、链条上每一版本完整文件 raw SHA、全部已消耗 challenge 与 ACK 不重复、严格字段、`registrar_public_hex` 与独立传入的值一致。**对最后一条记录**另外重新执行 EC303→EC294 真签证据重放，证明登记员最后一次签署的 claim 与最新提供的原证据完全相同。老条目对应的旧 ZIP/ACK **没有打包进登记历史，也没有在本次 verify 重新播放**：只有其登记员签名的历史声明得到认证。若需重审某笔旧交易，人工提供该笔原始 ZIP/ACK 与独立 pin，再用原 EC303 验证器做逐笔追溯。绝不能宣传“所有旧 ZIP 均本轮已重放”。

## 5. 退出码、容量和限制

`0` 表示当前**指定**的签名证据/历史/本次外部 SHA 相容；`3` 拒绝、`4` 输入有误、`5` 本机环境不可用。任何不确定、原签章冲突、上游 ZIP 与外部 SHA 不同、篡改历史后攻击者自行重算 SHA、公钥复用、重复挑战/ACK、输出文件已存在、上一次外部快照 SHA/序号不匹配都不会输出成功。最多**256 条记录 / 1.5MB 账本**；达到上限明确拒绝，没有暗含的清理或分页。登记员密钥撤销/轮换、外部 CAS/WORM、多机原子写、独立组织身份发放、挑战唯一发行、可信时间、防并发恶意本地改写、长周期分段审计不在本轮功能边界。

在真实 POSIX/Windows/macOS、共享盘/断电、真实两人多机和可信外部保管、生产 Provider/Inbox、原 PowerShell7 Smoke15、E63–E66/CI/Git 上均需后来用户统一验收；EC249/250/B001 和 global Quality PASS=false 保持不变。
