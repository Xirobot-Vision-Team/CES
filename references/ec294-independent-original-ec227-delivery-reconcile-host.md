# EC294：原 EC227 私有投递对账记录与本地 HMAC 审计回读——操作与安全手册

版本 `V6.04/R294`。只为**已有原 EC225 真实耐久 `03_SUBMIT_ATTEMPTED` 的一份原 EC288 私有任务**建立独立本地对账，不是一键发送/重试工具。Host 没有任何 `/submit` 或 EC225 `send_once` 路径。**所有命令应由不同权限的真实负责人分别审核和执行；示例占位值不可作为生产凭证。** 以下命令在解压后的 CES 工程根目录运行；目标系统需支持 Python + cryptography、可信本地 POSIX 文件系统、AF_UNIX、内核 peer UID、足够稳定的 UTC/时钟和完整离线原 EC288/EC293 授权材料。

## 1. 上游资料与本轮新保管物

先按照 `references/ec288-independent-delivery-send-host.md` 和 `references/ec293-independent-private-delivery-status-readback-host.md` 部署**原** EC225 私有发送和 EC226 只读状态 Host 的私有任务、信任锚、策略及凭据。原 EC225 签名任务与 `03_SUBMIT_ATTEMPTED` 必须真实存在；EC294 **绝不能自行生产或补造提交标记**。原 EC293 `policy` 的完整原始文件、SHA256 必须由另一渠道钉牢。EC294 会独立重验 EC221–225 的历史授权链，**从不读取原 EC288 写/发送 Token**。

在安全的私有目录创建唯一新的 `ec294-admission/`（`0700`），与原 EC225 的 outbox、EC293 的 admission 不共址。在本轮部署域中用下面命令分别创建两份 EC294 审批角色和一份 Host 回执角色的**不同 Ed25519 私钥**，必须由其相应实际管理员安全保存；各次只打印公钥，不打印私钥：

```bash
python -I -B scripts/ces_delivery_reconcile_host.py keygen-offline --private-out /secure/294-custodian.key
python -I -B scripts/ces_delivery_reconcile_host.py keygen-offline --private-out /secure/294-auditor.key
python -I -B scripts/ces_delivery_reconcile_host.py keygen-offline --private-out /secure/294-host-server.key
```

新建用于原 EC227 HMAC 链的**32 字节真正随机**私有审计秘钥；返回 `audit_hmac_sha256` 作为核对 pin，原文不会出现在输出中：

```bash
python -I -B scripts/ces_delivery_reconcile_host.py keygen-audit-hmac \
  --private-out /secure/294-audit.key
```

此密钥不可与旧 token 或密钥复用。**丢失/旋转 HMAC 秘钥会失去读取旧链能力**，不能在新链上假装延续历史。原所有业务公钥、EC288、原 EC226 与 EC293 和本轮 EC294 19 把必须两两不同；代码会核验这一约束。这里只能验证公钥不同，不能证明实体人员物理独立。

## 2. 显式 opt-in 生成策略、固定 SHA

```bash
mkdir -m 700 /secure/ec294-admission
python -I -B scripts/ces_delivery_reconcile_host.py prepare-policy \
  --ec293-policy-file /secure/ec293-policy.json \
  --ec293-policy-sha256 <EC293_POLICY_RAW_FILE_SHA256> \
  --audit-hmac-file /secure/294-audit.key \
  --admission-root /secure/ec294-admission \
  --allowed-uid <CLIENT_UID> \
  --custodian-public-hex <EC294_CUSTODIAN_PUBLIC_HEX> \
  --auditor-public-hex <EC294_AUDITOR_PUBLIC_HEX> \
  --server-public-hex <EC294_HOST_SERVER_PUBLIC_HEX> \
  --enable-private-reconciliation \
  --out /secure/ec294-policy.json
```

从返回 JSON 的 `policy_sha256` **在离线/外部渠道钉住**原始策略文件；不可接受后来同路径被替换的策略。策略还绑定父 EC293 Host 源码、原 EC227 源码、本轮协议/Host/操作源码 raw SHA、原 EC226 的代码和原任务/读 token 的 SHA，而不是授权修改旧工程。`--allowed-uid` 可重复传给经独立评审的必要 UID，不能用广泛的通用群组绕开校验。项目内不提供生产密钥或示例真实个人凭证。

## 3. 启动独立 Host

使用预先审批的私有 socket 目录（所有者正确、没有可写的不可信父目录、非软链接路径）运行：

```bash
python -I -B scripts/ces_delivery_reconcile_host.py serve \
  --socket /secure/ec294-audit.sock \
  --policy-file /secure/ec294-policy.json \
  --policy-sha256 <EC294_POLICY_SHA256> \
  --server-private-key-file /secure/294-host-server.key
```

独立部署/服务进程、ACL、systemd/操作系统时钟、外部链头保管、防回滚以及真正的组织签名独立性，需实际团队验证。本机 Host 单连接顺序处理；**不同进程或跨机共同读写同一 root 不承诺分布式原子性**。不要在网络文件系统直接依赖本机 `flock/fsync` 的含义。

## 4A. Record：一次新的 EC226 状态查询 + 原 EC227 两条耐久审计

为 **Record** 每次先由原 EC226 READ 保管角色准备短时的独立原读票；这是原 EC293 已用过的原 EC226 授权格式（`≤35s`），不是 EC225 发送许可：

```bash
python -I -B scripts/ces_delivery_reconcile_host.py prepare-read-template \
  --ec293-policy-file /secure/ec293-policy.json \
  --ec293-policy-sha256 <EC293_POLICY_RAW_FILE_SHA256> \
  --ttl-seconds 35 --out /secure/294-read-template.json
python -I -B scripts/ces_delivery_reconcile_host.py sign-read-offline \
  --template-file /secure/294-read-template.json \
  --private-key-file /secure/ec226-read-issuer.key \
  --out /secure/294-signed-read.json
```

**外部审计头在审批前必须已独立核定。** 对从未写过 EC227 审计的任务，`<EXPECTED_HMAC_HEAD>` 是**恰好 64 个 `0`**；对已有审计的任务，必须是上一个完整独立保管的 Host 签名回执里已核实的 `audit_head_hmac_sha256`，而不是从当前易变目录自动取得的新值。确认 `ec227-*` 日志/`ec226-read-*` nonce/`ec294-*` 账本与这个头一致且无异常后，准备本轮短票 subject：

```bash
python -I -B scripts/ces_delivery_reconcile_host.py prepare-offline \
  --policy-file /secure/ec294-policy.json \
  --policy-sha256 <EC294_POLICY_SHA256> \
  --mode record --uid <CLIENT_UID> --ttl-seconds 25 \
  --expected-head <EXPECTED_HMAC_HEAD> \
  --read-grant-file /secure/294-signed-read.json \
  --out /secure/294-record-subject.json
python -I -B scripts/ces_delivery_reconcile_host.py sign-custodian-offline \
  --subject-file /secure/294-record-subject.json \
  --private-key-file /secure/294-custodian.key \
  --out /secure/294-record-custodian-vote.json
python -I -B scripts/ces_delivery_reconcile_host.py sign-auditor-offline \
  --subject-file /secure/294-record-subject.json \
  --private-key-file /secure/294-auditor.key \
  --out /secure/294-record-auditor-vote.json
python -I -B scripts/ces_delivery_reconcile_host.py assemble \
  --subject-file /secure/294-record-subject.json \
  --custodian-vote-file /secure/294-record-custodian-vote.json \
  --auditor-vote-file /secure/294-record-auditor-vote.json \
  --custodian-public-hex <EC294_CUSTODIAN_PUBLIC_HEX> \
  --auditor-public-hex <EC294_AUDITOR_PUBLIC_HEX> \
  --out /secure/294-record-grant.json
```

在相同 ≤25 秒票有效期内**仅执行一次**（服务端所有授权都以真实当前时钟重新核验，不能事后重放）：

```bash
python -I -B scripts/ces_next.py host-delivery-reconcile DeliveryReconcile Record \
  --socket /secure/ec294-audit.sock \
  --grant-file /secure/294-record-grant.json \
  --read-grant-file /secure/294-signed-read.json \
  --policy-sha256 <EC294_POLICY_SHA256> \
  --server-public-hex <EC294_HOST_SERVER_PUBLIC_HEX>
```

原 EC227 先 `LOOKUP_STARTED` 耐久落盘，再由原 EC226 为新的 read nonce 耐久记账，执行固定 `POST /status`，最后原 EC227 追加 `LOOKUP_RESULT` 耐久落盘；若中途失败，有可能只出现第一条。状态结果 `partial/2` 并非业务已送达，必须逐字段理解 `delivery_state`、签名 Inbox 证据和 `audit_head_hmac_sha256`。

## 4B. Readback：只读校验原 EC227 本地审计（无状态读票、无网络）

**不得**提供 `--read-grant-file`，仅使用新 EC294 的两张短签 subject `--mode readback`，仍需上一步的**独立**预期审计头。在历史不足或没有日志时，结果可能为 `unavailable/5`，不能视为已投递；本次 `delivery_state` 固定为 `UNKNOWN_UNCONFIRMED`，以 `last_historical_attested_state` 另行标识历史证据。

```bash
python -I -B scripts/ces_delivery_reconcile_host.py prepare-offline \
  --policy-file /secure/ec294-policy.json \
  --policy-sha256 <EC294_POLICY_SHA256> \
  --mode readback --uid <CLIENT_UID> --ttl-seconds 25 \
  --expected-head <INDEPENDENTLY_STORED_HEAD> \
  --out /secure/294-readback-subject.json
# 对上述 subject 分别执行 sign-custodian-offline、sign-auditor-offline 和 assemble，
# 使用独立的新文件名 294-readback-*.json，切勿复用 Record 的 grant 或签名。
python -I -B scripts/ces_next.py host-delivery-reconcile DeliveryReconcile Readback \
  --socket /secure/ec294-audit.sock \
  --grant-file /secure/294-readback-grant.json \
  --policy-sha256 <EC294_POLICY_SHA256> \
  --server-public-hex <EC294_HOST_SERVER_PUBLIC_HEX>
```

**签名 ACK 也需单独保留**。客户端严格检验回复对请求 nonce/hash、原任务、策略、公钥、时间和原业务结果语义的完整签名绑定。此读取不会打开任何 Provider token，也不会生成新的 original EC226 read nonce，仍消耗一次 EC294 Host admission。

## 5. 不可自动修复的边界与统一终验

- **丢 ACK/超时/中途断电：** 把结果视为 UNKNOWN，**绝不重放同一 EC294 grant 或原 EC226 read nonce，更不再次发送 EC225 消息**。原 EC227 可能刚写 `LOOKUP_STARTED` 就断电：独立鉴别日志完整性/可信外部头后，另审批只读 `Readback`；未知记录不得作为已查明的送达。
- **本机链回滚/篡改：** HMAC 能拒绝现存条目被改写；不能反查有人完全抹去最后几个有效条目。只有链头外部存储、离机签名回执和实际组织控制能提供防回滚能力。若链头失配，**停止 Record**，不要把独立头改成可疑当前值或清空目录。
- **生产密钥/角色：** 19 个数学上不同的公钥不代表 19 位自然人或不同机器；若同一管理员握有两把私钥，保护需求仍不满足。必须单独审批权限、网络固定 Provider 状态接口、读 token 确实不可提交、签名观测者和审计链的脱机保管。
- **容量/并发：** 原 EC227 审计 64 条上限，单机 POSIX `flock`/fsync；不支持自动裁剪、扩容、改键后伪造旧历史或多主机共识。满载后停止并人工制定新版本迁移方案，不在 EC294 隐式清理。
- **需要用户统一终验：** 原 PowerShell7 15 Smoke，Windows/macOS 行为、真实 Provider TLS/签名/inbox、一致的 UTC/NTP、ACL/断电后 fsync、跨进程竞争和日志保留/灾难恢复、独立审计头公证、组织密钥职责、远端 Git/CI/Provider、E63–E66 和完整 CES 联合验收。本轮 91/91 仅代表本地合成签名 Provider/Inbox 的真实原业务代码和本地原审计路径测试；EC249/250/B001/全局 Quality PASS 的未达状态均保留。
