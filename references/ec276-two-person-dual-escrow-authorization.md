# EC276 — 双站 Escrow 记录的线下双人授权与严格 Host

> 完整工程版 **V5.86/R276/EC276**；本轮只增加一个 opt-in 功能。原 EC275 双站 CAS、原 EC274 守护进程、EC273/272 严格 Host、PowerShell V4.60/R150、Router V5.53/R243 均保持原样。**不要**把本地三名签署者视为已经被证明独立的现实自然人。

## 1. 为什么需要新层，以及它究竟授权什么

EC275 已经要求两个独立 TLS/Ed25519 authority 在当前最新 EC272/273 主题、同一个完整 SHA head 上签名 fresh read，并提供非原子、可人工恢复的双站 CAS。但过去的操作 CLI 接受操作者直接键入的 `--record-sha256`、`--expected-previous-sha256` 与两站 endpoint/pin；一旦批准后的调用被改成另一组输入，旧 CLI 本身没有额外的**两人审批清单**。

EC276 新增独立的线下批准阶段：一个 canonical `INTENT.json` 完整包含**原已完成两个见证 Ed25519 签名**的 EC274 record，记录完整 SHA、精确前驱 SHA/record_index、namespace、recovered root SHA、closure SHA、三名 witness 公钥指纹、三名**不同的 operator approver** 公钥指纹，以及 A/B 两站各自的 hostname、port、CA PEM SHA、TLS leaf DER SHA、escrow signing public SHA。它还包含独立 nonce、UTC 秒整数形式的 `not_before_unix` 与 `expires_at_unix`（不超过 **72 小时**）。签名消息为 `CES/EC276/two-person-dual-escrow-intent/v1\0` + canonical intent bytes；必须由独立三名 approver 公钥中**恰好两名不同**的私钥分别签署，按公钥 SHA 升序组装到 `APPROVAL.json`，然后对完整 APPROVAL 的 SHA-256 做操作方的**带外信任锚**。

新 **`advance-approved`** 从已签 APPROVAL **读取目标 record、前驱、两个 site 身份**；不会接受额外的 `--record` / `--record-sha256` / `--expected-previous-sha256` 参数重新定义目标。它必须验证两人签章、当前允许的时间窗口、三名 approver 公钥文件 SHA、不能复用 witness/escrow/root 私钥的角色约束、完整 record 的两名见证真签名，以及 EC275 的**双站实际前驱/目标验签读回 + CAS**。签章过期或站点身份变动均失败关闭。既有 EC275 原接口并未被删除、改写或强制升级；要强制审批只能通过**运维权限与服务入口隔离**只允许调用新入口。

## 2. 密钥与目录准备

- A、B 两站在**不同机器、不同 CA、不同 escrow 回包 Ed25519 签名公钥、不同 TLS leaf、不同 journal 及独立治理者**管理；其守护进程沿用原 EC274 `daemon.py`。两个同机端口**不满足**现实独立托管要求。
- 三名独立 operator approver 各持有**自己的原始 32 字节 Ed25519 私钥**；公钥为原始 32 字节，SHA-256 的 lowercase hex 在**带外受保护清单**独立固定。不允许与 EC274/271 witness、A/B escrow、公钥化治理 root、Host 活动审计/custody 签署者复用。离线签署者分别阅读并批准同一 intent 完整 SHA、记录/前驱、两站 fingerprints、有效时间。
- 所有输入和输出应在 owner-private 0700 目录内，以 0600 文件保存；新文件由 `O_EXCL`/`fsync` 方式创建，重复运行不能覆盖已审签文件。`approval` 与 approver 公钥不能放在业务 Git 工作区、审核输入或活动审计树，也不能与其它 Host 信任文件复用路径。
- 现实 approver 人员隔离、设备证明、操作记录、跨节点物理存储不可回退、外部不可变独立 head/索引、外部可信 UTC 与生产 CA 撤销都**不是**本轮代码可以自动证明的东西。应在最终联合验收时提供明确证据。

## 3. 三名操作审批人双签的五个步骤

首先按 [EC274 原手册](ec274-independent-remote-monotonic-escrow.md) 从完整 EC272/273 验证得到一个 canonical `RECORD.json`，经过原三位 witness 公钥中的**两位**线下签署并组装；这两个 witness 签名与下面的两个 **operator approver** 签名是不同的职能和不同密钥。准备前须核对 record 本身包含正确的前驱 SHA、连续 sequence/checkpoint/governance epoch 和预期当前主题。下面 `COMMON` 与 `APPROVERS` 均表示明确提供的 CLI 参数，不表示从目录自动发现的信任锚：

```bash
COMMON=(
  --escrow-host escrow-a.example.net --escrow-port 9443
  --escrow-namespace example-project-a
  --escrow-tls-ca /trust/site-A-ca.pem --escrow-tls-ca-sha256 "$A_CA_SHA"
  --escrow-tls-leaf-sha256 "$A_LEAF_DER_SHA"
  --escrow-public /trust/site-A-escrow.raw --escrow-public-sha256 "$A_SIGNER_SHA"
  --secondary-escrow-host escrow-b.example.net --secondary-escrow-port 9443
  --secondary-escrow-tls-ca /trust/site-B-ca.pem --secondary-escrow-tls-ca-sha256 "$B_CA_SHA"
  --secondary-escrow-tls-leaf-sha256 "$B_LEAF_DER_SHA"
  --secondary-escrow-public /trust/site-B-escrow.raw
  --secondary-escrow-public-sha256 "$B_SIGNER_SHA"
  --root-sha256 "$RECOVERED_ROOT_PUBLIC_SHA"
  --closure-sha256 "$RECOVERY_CLOSURE_SHA"
  --freshness-witness-public /trust/w1.raw --freshness-witness-public-sha256 "$W1_SHA"
  --freshness-witness-public /trust/w2.raw --freshness-witness-public-sha256 "$W2_SHA"
  --freshness-witness-public /trust/w3.raw --freshness-witness-public-sha256 "$W3_SHA"
)
APPROVERS=(
  --approver-public /trust/operator1.raw --approver-public-sha256 "$OP1_SHA"
  --approver-public /trust/operator2.raw --approver-public-sha256 "$OP2_SHA"
  --approver-public /trust/operator3.raw --approver-public-sha256 "$OP3_SHA"
)

# 1. 从原已双见证批准的 record 生成新的线下双人审核意图：不联系 A/B，
#    它只核对本地公钥和签名。NOT_BEFORE/EXPIRES 为由操作者批准的 UTC 秒。
python construction/ec276_dual_approval_host/operator.py prepare-intent \
  "${COMMON[@]}" "${APPROVERS[@]}" \
  --record /private/RECORD.json --record-sha256 "$RECORD_SHA" \
  --expected-previous-sha256 "$PREVIOUS_RECORD_SHA" \
  --not-before-unix "$NOT_BEFORE" --expires-at-unix "$EXPIRES" \
  --output /private/INTENT.json

# 2. 审批人一、二分别将 *完全相同* 的 INTENT.json 和独立确认的 SHA
#    带到各自离线设备，用本人私钥签署；不得将私钥复制到在线 Host：
python construction/ec276_dual_approval_host/operator.py sign-intent \
  --intent /private/INTENT.json --intent-sha256 "$INTENT_SHA" \
  --approver-secret /offline/operator1-secret.raw \
  --approver-public-sha256 "$OP1_SHA" --output /offline/VOTE-1.json
# 审批人 2 重复，输出 VOTE-2.json；每份 VOTE 的 SHA 须独立固定。

# 3. 联机操作者只持有公钥、两个投票文件和固定 SHA，组装审批授权：
python construction/ec276_dual_approval_host/operator.py assemble-approval \
  "${COMMON[@]}" "${APPROVERS[@]}" \
  --intent /private/INTENT.json --intent-sha256 "$INTENT_SHA" \
  --approval-vote /private/VOTE-1.json --approval-vote-sha256 "$VOTE_1_SHA" \
  --approval-vote /private/VOTE-2.json --approval-vote-sha256 "$VOTE_2_SHA" \
  --output /private/APPROVAL.json

# 4. 签名批准的预检查：两站必须都活着，各是精确前驱或精确目标。
python construction/ec276_dual_approval_host/operator.py inspect-advance-approved \
  "${COMMON[@]}" "${APPROVERS[@]}" \
  --approval /private/APPROVAL.json --approval-sha256 "$APPROVAL_SHA"

# 5. 受审批范围约束的 A/B 两站 CAS，再做双站 fresh nonce signed read：
python construction/ec276_dual_approval_host/operator.py advance-approved \
  "${COMMON[@]}" "${APPROVERS[@]}" \
  --approval /private/APPROVAL.json --approval-sha256 "$APPROVAL_SHA"

# 只读查看 A/B 是否都已到达 exact approved head：
python construction/ec276_dual_approval_host/operator.py inspect-approved \
  "${COMMON[@]}" "${APPROVERS[@]}" \
  --approval /private/APPROVAL.json --approval-sha256 "$APPROVAL_SHA"
```

`sign-intent` 是**唯一**使用 `--approver-secret` 的命令；其 CLI 不需要或允许双站/CA/见证参数。其他命令只使用审批人公钥。上述时间和 SHA 变量需要从**独立审批流程**明确赋值，不应依赖读取不可信本地缓存或根据远端“当前最新”自动推断批准值。

## 4. 严格服务端（全套 EC275 参数均不可省略）

```bash
# 先把原 EC275 verify-gate 所有必填及信任钉住参数完整放入此 shell 数组，
# 特别包括 --escrow-record-sha256 及 A/B 各自的 minimum-index。
# EC275_HOST_ARGS=( ... )
python construction/ec276_dual_approval_host/serve.py verify-gate \
  "${EC275_HOST_ARGS[@]}" \
  --approval /trust/APPROVAL.json --approval-sha256 "$APPROVAL_SHA" \
  --approver-public /trust/operator1.raw --approver-public-sha256 "$OP1_SHA" \
  --approver-public /trust/operator2.raw --approver-public-sha256 "$OP2_SHA" \
  --approver-public /trust/operator3.raw --approver-public-sha256 "$OP3_SHA"
```

`serve` 同样追加上述参数，继承 `--socket`、`--max-sessions`、`--accept-timeout`。**父 EC275 的 `--escrow-record-sha256` 必须逐字节等于授权 record 的 SHA；A/B `--escrow-minimum-index`、`--secondary-escrow-minimum-index` 都必须等于授权 record_index**。启动前、会话 begin 前及每个受守护操作前后验证 pinned 文件完整 SHA、**两名真实离线审批签章**、三名角色分离公钥、有效期，随后仍必须通过旧 Host 的完整 Git/来源/恢复/治理/EC272 双签/EC273 TSA/两站实时签名读取/Lease/审计/主动撤权。任何错误失败关闭，不降级原 EC275 或读取“最后通过”的旧授权缓存。

运行期使用 wall clock + monotonic anchor + 历史最大观察时间限制回拨；**跨重启可信时间/外部 UTC** 仍须另行保障。有效期届满将阻断新的会话，并可撤销正在运行的会话；部署时须选择足够运行窗口，**本轮不会**在允许期后自动续期或静默批准新版记录。

## 5. 半提交/到期/轮换的处置

- A 站已提交、B 站未提交或提交结果不确定时，不能标记“完全同步”，也不能生成另一份候选 record 来掩盖半提交。先恢复连接，核验 A/B 的签名 read 与原 record/previous SHA；有效期内使用**同一 APPROVAL 和 record** 再次执行 `inspect-advance-approved` → `advance-approved`。
- **如果原 APPROVAL 已到期：** 两名合法审批者可针对**完全相同的原 record bytes/SHA、前驱 SHA、两站身份**重新独立签发新的有效期 `INTENT/APPROVAL`；不能改变目标记录或自行修改远端日志。任何中间不一致仍应停服人工处置。
- 如果需要更换 A/B 的 CA、TLS 叶证书、host、签名私钥、信任路径或三位批准者名单，旧 APPROVAL **无效**；另行治理新 site 信任锚并对同一/后续目标发起新一轮离线双签，不做在线静默 rebind。本代码未设计自动在线 key rotation。
- `verify-gate` 不是单独的业务准入授权，只有在业务 Host 的真实受保护 session 所有父检查与上下游治理完成时才可执行业务。新层不会把旧 Router 的 11 个 `HOST_REQUIRED` route 解锁。

## 6. 施工验证与延后统一验收

可在 non-root POSIX + Python cryptography + Git + OpenSSL 环境运行（本轮已经本地执行）：

```bash
PYTHONPATH=construction python construction/ec276_dual_approval_host/test_approval.py
PYTHONPATH=construction python construction/ec276_dual_approval_host/test_host.py
PYTHONPATH=construction python construction/ec275_dual_escrow_host/test_quorum.py
PYTHONPATH=construction python construction/ec275_dual_escrow_host/test_host.py
```

EC276 核心包括原生 localhost 两 TLS、签名绑定、tamper 拒绝、操作 CLI、半提交恢复；严格 Host 包括真实 Git/TSA/socket/Lease/signed audit/active deny 的组合，OCI/cgroup **mock**。所有审批人、TLS CA、Escrow 站、TSA 均为本机合成，不代表具备现实独立 HSM/人类分离和不可回退 WORM。原生 PowerShell7 15 Smoke、Windows/macOS E63–E66、11 Router HOST_REQUIRED、生产 OCI+cgroup v2、真实异地双站重启/分区、生产 CRL/OCSP、可信 TSA/UTC、外部不变性凭据、全系统最终验收均待后续**统一人工协助**完成。

当前工程继续保留 EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、final acceptance `NOT_STARTED`；**不声称全局 Quality PASS**。
