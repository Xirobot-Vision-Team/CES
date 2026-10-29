# EC291 — 原 EC230 `DocsOnlyPublish` 私有 Git 候选引用独立回读宿主

**版本：V6.01 / R291 / EC-291；一轮仅施工 EC291。** 此可选、单独部署的 AF_UNIX 宿主仅提供一条新业务链：对原 EC285 已通过**原封未修改的 EC229** `DocsOnlyPublisher.publish_once` 留下持久 journal 的**同一份** owner-private Git 文档候选操作，实际调用**原封未修改的 EC230** `publication_receipts.PublicationReceiptService.inspect_docs` 重新独立读取本地私有 bare 仓的准确引用、父节点与候选内容和原证据。它不是执行 publish、不是清理工作树、不是向远端 Git 推送、更不是生产或公众已发布证明。

## 必须区分的四层身份 / 权限

1. **原 EC229 的四张原始真实签名。** Job 必须来自 EC285 原格式、准确指向原 repository/HEAD、审核文档的 SHA、Git worktree、私有 bare、journal、四名原业务签发角色的完整原许可。宿主从管理员 0600 私有 Job 加载并重验；客户端不能在 socket 上替换原文、路径、目标引用、Git 参数、回调、签发根或密钥。
2. **原 EC230 两个新的独立根：READ + CLEANUP。** 本轮仅允许原 `READ_DOMAIN` 对 `DocsOnlyPublish` 这次 operation/target/original-grant/nonce/epoch/原始 EC230 代码修订的单次短期签名读授权。`cleanup_public_hex` 是原结构要求的分立公钥，占位授权根**不赋予任何 cleanup 能力**；`enable_clean_linked_worktree=False`。本轮不持有任何 cleanup 私钥。
3. **本轮 EC291 两张额外、彼此域分离的精确线下授权。** 私有仓保管者 `custodian` 和独立观察者 `inspector` 分别签同一 EC291 Subject，精确绑定原四签 Job SHA、原 EC230 read grant SHA、原/宿主源码 SHA、policy、操作/目标/原 grant SHA、内核 Unix peer UID、随机一次性 host grant 和不超过 25 秒的有效期。五把新公钥（READ、CLEANUP、custodian、inspector、host server）与原四把 EC229 业务公钥 **九把两两不同**；这只是密钥唯一性，**不证明九个真实独立的人**。
4. **内核 Socket 身份 + 第三方宿主签名回复。** 不接受请求 JSON 自述 UID。仅由 Unix `SO_PEERCRED`/`getpeereid` 取 peer UID 再按 owner policy allowlist 比对。服务端签名封装原函数结果及确切 request SHA/nonce/policy/job SHA，客户端用单独 pinned server 公钥验签；看不到签名 ACK 或 ACK 失真一律是 UNKNOWN，不能当成 Git 引用不存在。

## 两套真正落盘的单次读取屏障

- **前置证据门：** 原 EC229 `ec229-<operation>/06_PUSH_ATTEMPTED` 必须在原 journal 中、且原 EC230 `_base` 重新比对原签名/请求/审批重叠区间。这里只代表原 EC229 私有写入*已经被尝试*，不是读成功，也不是允许重新写。
- **第一道授权消费：** EC291 `admission/ec291-<host-grant-id>/00_ADMISSION.json` O_EXCL 持久创建并 fsync 文件、子目录、父目录。缺口/损坏/已消耗都不得凭新的 Socket 请求自动重放；最多只允许人工核查后重新独立审批。
- **第二道真正读取消费：** **原 EC230 不变的代码**以 `ec230-read-<inspection-id>/00_CLAIM`/`01_ATTEMPT` 和最终 `02_OBSERVATION` 独立 fsync，验证原 EC230 read nonce 不可复用；然后直接读**本地私有** bare Git（原 EC230 内部精确验证 commit/ref/parent/content）。本轮不调用 `DocsOnlyPublisher.publish_once`、不执行原 EC230 cleanup、不会对外 HTTPS GET、POST 或 Git push。
- **竞态语义：** 授权/时钟和 Git 读取不可能做到对整套文件、全部原 journal、Git refs 和 OS 时钟的跨进程原子快照。读前读后检查 owner pin，遇失联、异常或 drift 必须报告 UNKNOWN、人工查原 EC229 journal + EC291 admission + 原 EC230 read audit + 私有 bare ref。绝不基于一个错误返回自动重试，也不能“顺手 cleanup”。

## 管理员部署与离线签发示例

必须使用真实绝对路径和部署前验过的 POSIX 权限、可用 Git 和 Python `cryptography`；命令中的 `READ`, `CLEANUP`, `CUSTODIAN`, `INSPECTOR`, `SERVER`, `POLICY_SHA`、UID `1000` 都是**示例占位符**。私钥应在分别受控的离线持有者环境，**不得打入分发 ZIP**，不要把密钥放到工作树，角色之间也不要共享。原 EC285 Job 请按 [原 EC285 操作手册](ec285-independent-docs-local-sandbox-host.md) 先准备；必须重用原四张业务授权的完整准确记录而非客户端补造。只有 EC285 真正留下的候选提交可以回读。

```bash
# 各角色先分别生成并线下托管独立 Ed25519 公私钥，可从以下离线工具获取 public_hex：
python3 -I -B scripts/ces_docs_receipt_host.py keygen-offline \
  --private-out /offline/one-role.key

# Owner 准备固定 policy。audit/admission 须是已存在 0700 的互不重叠私有目录，
# 也不得位于原仓、journal、bare Git、工作树或受审 Job 目录之内。
python3 -I -B scripts/ces_docs_receipt_host.py prepare-policy \
  --job-file /owner/exact-original-ec285-job.json \
  --audit-root /owner/ec230-docs-read-audit \
  --admission-root /owner/ec291-docs-admission \
  --allowed-uid 1000 --read-public-hex READ --cleanup-public-hex CLEANUP \
  --receipt-epoch 7 --custodian-public-hex CUSTODIAN \
  --inspector-public-hex INSPECTOR --server-public-hex SERVER \
  --enable-one-private-docs-readback --out /owner/ec291-policy.json

# 先启动独立服务；不要先签发 25 秒的短票再慢慢启动进程。
python3 -I -B scripts/ces_docs_receipt_host.py serve \
  --socket /owner/socket/ec291-read.sock \
  --policy-file /owner/ec291-policy.json --policy-sha256 POLICY_SHA \
  --server-private-key /owner/keys/ec291-server.key

# 以下用各签发者独立终端，在服务已启动、紧邻单次回读操作时完成。
# 原 EC230 READ 授权仅 1..35 秒，read grant 的确切 epoch/operation/read nonce 必须吻合。
python3 -I -B scripts/ces_docs_receipt_host.py prepare-read-template \
  --policy-file /owner/ec291-policy.json --policy-sha256 POLICY_SHA \
  --ttl-seconds 34 --out /owner/ec230-docs-read-template.json
python3 -I -B scripts/ces_docs_receipt_host.py sign-read-offline \
  --template-file /owner/ec230-docs-read-template.json \
  --private-key-file /offline/ec230-read-only.key \
  --out /owner/ec230-docs-read-grant.json

python3 -I -B scripts/ces_docs_receipt_host.py prepare-offline \
  --policy-file /owner/ec291-policy.json --policy-sha256 POLICY_SHA \
  --read-grant-file /owner/ec230-docs-read-grant.json \
  --uid 1000 --ttl-seconds 24 --out /owner/ec291-subject.json
python3 -I -B scripts/ces_docs_receipt_host.py sign-custodian-offline \
  --subject-file /owner/ec291-subject.json \
  --private-key-file /offline/custodian.key --out /owner/custodian.vote
python3 -I -B scripts/ces_docs_receipt_host.py sign-inspector-offline \
  --subject-file /owner/ec291-subject.json \
  --private-key-file /offline/independent-inspector.key --out /owner/inspector.vote
python3 -I -B scripts/ces_docs_receipt_host.py assemble-offline \
  --subject-file /owner/ec291-subject.json \
  --custodian-vote /owner/custodian.vote --inspector-vote /owner/inspector.vote \
  --custodian-public-hex CUSTODIAN --inspector-public-hex INSPECTOR \
  --out /owner/ec291-two-vote-grant.json

# 精确可选入口：并非 Router `run DocsOnlyPublish LocalSandbox` 的权限升级。
python3 -I -B scripts/ces_next.py host-docs-receipt DocsOnlyPublish Readback \
  --socket /owner/socket/ec291-read.sock \
  --grant-file /owner/ec291-two-vote-grant.json \
  --read-grant-file /owner/ec230-docs-read-grant.json \
  --policy-sha256 POLICY_SHA --server-public-hex SERVER
```

服务端固定一次预配的原 Job、所有原源码 SHA 和私有路径，不提供通用 TCP、HTTP API，Socket 请求仅载两组原始签名票和 nonce。给这些票使用 0600 私有文件，给服务根目录 0700 权限，Unix Socket 父目录 owner/group ACL 必须经本机管理员审查。可在 `scripts/ces_docs_receipt_host.py submit ...` 直接使用完全同样的客户端验签路径；统一控制台会再检查返回结果的保守声明。若运行于无内核可信 peer UID 的平台，此宿主直接拒绝，而不是退化为客户端自报身份。

## 精确结果与处理

| 回执 | 代表什么 | **明确不代表什么** |
| --- | --- | --- |
| 原 EC230 `partial/2` + `VERIFIED_PRIVATE_LOCAL_REF_ONLY` | 在这一次独立授权读取中，原 EC230 已重新验证**本机私有 bare Git** 精确候选引用与内容，并留下 read audit | **不是**公有/生产发布、合入主干、远程仓库存在、CI 通过或可见 |
| 原 EC230 `partial/2` + `UNKNOWN_PRIVATE_REF_ABSENT` | 本次读取没得到正面 ref 证据，记为 UNKNOWN | **不能**断言历史从未写入、不会竞态存在或任何远端不存在 |
| EC230 `blocked/4`、`unavailable/5`，或 EC291 `permission_denied/3` | 签名、账本、时效、身份、Git 状态、SHA pin 或检查不满足；已签名的拒绝不能升格成功 | 不可认为未尝试读取、不应自动签一套新票重复执行 |
| 无可信已签名 ACK / Socket timeout / 源数据权限 drift | **UNKNOWN；**EC291 admission 和 EC230 audit 可能已经消费甚至读取过 Git | 不可自动重读、补写、Git push、删除任何工作树或 refs |

缺失 `06_PUSH_ATTEMPTED` 时连 EC291 授权消费都不应发生。若 EC230 已消耗读票，不得靠换 EC291 两张新 host 票绕过原 nonce 一用关口。两个 durable 阶段在本地 POSIX 测过，但生产存储、异常掉电与多节点并发没有验证；前置 `enable_one_private_docs_readback` 是单 scope 许可，不代表扫描多个任务或给通用发行权限。

## 已完成的开发功能 vs 统一待验

- **真实本地功能验证：** 新 EC291 14/14 个测试；原 `test_publication_receipts` 28/28、原 `test_docs_only_publish` 30/30、父 EC285 Host 18/18，即**90 个互不重复的聚焦用例**全部通过。确实先由**原 EC229** 在真正一次性本地 Git 仓创建 commit/private bare ref 和 journal，再由**原 EC230** 在独立 Unix 进程链中读取并生成原 read audit；原来的拒绝路径/签名、宿主票、UID、nonce 重放、错误 Git ref、缺审计 marker、控制台拒绝全部测试。使用临时 Git 和本机生成的测试密钥，没有真实远端 Provider HTTP，也没有外网推送。
- **须用户协助的真实部署验收：** 原 EC285 Job 四原签的真实组织可信来源、新的 READ/CLEANUP 和 EC291 三把宿主根真实物理/权限分离、可靠 UTC 与紧急撤销传播、所有实际 POSIX UID/ACL 和 fsync 断电保持、原本地 Git 仓安全 provenance/权限与多节点争抢、Windows/macOS 和 Linux 生产差异、原 PowerShell7 15 Smoke、Git/CI/远端可见性、E63–E66、最终用户验收。所有这些当前均**未声称通过**。
- **隔离保持：** 原 Router 74 固定路由及 11 条 `HOST_REQUIRED run` 默认拒绝、原 EC229/230、本地 R150 PowerShell 和 EC279–290 所有旧 Host 未修改。EC249 `FULL_FUNCTION_NOT_COMPLETE` / EC250 `BLOCKED` / B001 `OPEN` / final acceptance `NOT_STARTED` / global Quality PASS=false。

参见 [EC291 记录](../EC-291.md) · [Scope](../construction/EC291_SCOPE.json) · [local report](../construction/EC291_LOCAL_REPORT.json) · [完整交付 SHA256](../construction/EC291_DELIVERY_SHA256.json)。
