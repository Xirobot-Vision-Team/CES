# EC269 — 预授权紧急治理根恢复：操作员指南（独立 opt-in）

> 适用工程包 **V5.79/R269/EC269**。这是一个**新的、独立的严格宿主/离线签署入口**，不是将原 EC268 三方正常交接改成无条件绕过旧根。服务端仍返回 `partial/2`；任何 `unavailable/5` 都不得作为准入成功。

## 1. 解决的具体故障

EC268 正常根交接要求旧根、新根与见证方各签一次；**旧根私钥意外不可用，导致无法再签署旧根交接**是独立故障。本 EC 只支持一种事先准备过的恢复：

1. **事故之前**，旧根仍可用且旧根 EC267 已签治理仍在有效窗口时，旧根用 Ed25519 签发一个、且仅一个由操作员独立 SHA Pin 固定的**恢复章程**。章程绑定旧根公钥、旧已签治理完整文件 SHA、旧 epoch、三个**指定且相异**的恢复委员会公钥指纹、固定 **2-of-3** 门槛及 `not_before/expires_at`，上限 **90 天**。章程时间只是本机/签发方的时间声明，不能证明独立可信时间。
2. **事故之后**，必须有一份原始旧根公钥可验证的旧 EC267 已签治理及其完整文件；新根使用自己的 Ed25519 私钥签发**epoch N+1**、`previous_governance_sha256` 等于旧治理完整文件 SHA 的新 EC267 治理（仍适用 ≤24h 有效期）；旧根不再需要私钥。
3. `prepare-recovery` 先验历史旧治理、旧根签章程、新治理的**新根签名**、原 EC268 `_transition` 的连续 epoch/完整前序 SHA/累计撤销与退役角色密钥明确撤销、根/委员/签源/保管签名方角色隔离，输出不可覆盖的规范声明草稿。
4. `sign-recovery` 要求新根先签、然后任选**两名**章程指定的不同委员签。为避免同一证书有多种排序，委员按 SHA 指纹**字典序升序**签署；委员可以选择 A+C、A+B 或 B+C，但必须按选定两人 SHA 升序。每次签署必须从签署方**独立提供的完整上一阶段文件 SHA**、全部旧/新治理和章程 Pin、公钥文件重新核验之前签名，且每次输出只能新建、0600、`O_EXCL`/fsync。
5. `verify-gate` 和 `serve` **从不接受上述任何根/委员私钥**，只用新/旧根公钥、三名委员公钥、两份完整旧/锚治理、旧根已签章程、**完整两票 + 新根签章证明**及独立 SHA Pin。运行前、每次 begin 和活跃会话全过程验证，任何凭据缺失、时限失效、目录混放、角色/撤销/签名/内容变化都失败关闭；继续采用原 EC265 已签归档保管、EC264 审计、EC266 源签名、EC253 租约与强制回收、EC257 OCI/cgroup、EC260/261 即时撤权及缓慢客户端清理。
6. 恢复锚 N+1 以后，新根可沿用 EC268 **最多 32 次**经过 SHA 固定的逐 epoch 治理续签链；每个中间文档必须仍保存且有效签名，当前文件依然满足 EC267 的实时 24h 规则。**恢复章程必须在每次服务核验时仍处于自身的恢复有效窗口，过期直接拒绝**；请在到期前显式迁移到按正式审批的新正常交接/信任锚流程。本轮不自动换锚、不续命。

### 必须单独保管的东西

- 旧根历史 Ed25519 **公钥**及旧 epoch N 完整签名治理和 SHA。
- 由旧根**事先签署**的不可覆写恢复章程，三个委员会公钥及各自独立指纹。
- 新根公钥及已签锚治理 N+1；新根私钥只给离线签署人员。
- 分别保存新根签、委员第 1 票、委员第 2 票的**完整文件和每一阶段 SHA**，以及最终完整证书独立固定的 SHA。
- 原 EC253/265/266/267 的原始源、票据、保管链、审计密钥和 operator 配置；所有治理材料必须位于受约束的私有存储目录，而不是 Git 源库或任何审计树。

## 2. 操作顺序

命令入口（在 `ces/` 工作目录下）：

```bash
python3 -I -B construction/ec269_emergency_recovery_host/serve.py --help
python3 -I -B construction/ec269_emergency_recovery_host/serve.py prepare-charter --help
```

以下是结构示例，`$...` **全部代表操作员独立取得并复核的确切文件/Pin**。不允许把签名输出自身读回得出的 Pin 当作外部独立审批。私钥不得传给 `verify-gate`、`serve`。三个公钥参数必须各自出现三次并分别配对。

```bash
# 第 0 步：旧根未遗失时。过期时间需由操作员给定，最长旧章程签发后 90 天。
COUNCIL_ARGS=(
  --council-public "$COUNCIL1_PUBLIC" --council-public-sha256 "$COUNCIL1_PIN"
  --council-public "$COUNCIL2_PUBLIC" --council-public-sha256 "$COUNCIL2_PIN"
  --council-public "$COUNCIL3_PUBLIC" --council-public-sha256 "$COUNCIL3_PIN"
)
OLD_ARGS=(
  --old-governance "$OLD_GOV" --old-governance-sha256 "$OLD_GOV_PIN"
  --old-root-public "$OLD_ROOT_PUBLIC" --old-root-public-sha256 "$OLD_ROOT_PIN"
)

python3 -I -B construction/ec269_emergency_recovery_host/serve.py prepare-charter \
  "${OLD_ARGS[@]}" "${COUNCIL_ARGS[@]}" \
  --expires-at-unix "$CHARTER_EXPIRES_UNIX" --output "$CHARTER_DRAFT"

# CHARTER_DRAFT_PIN 必须由章程签署者在独立通道复核。
python3 -I -B construction/ec269_emergency_recovery_host/serve.py sign-charter \
  "${OLD_ARGS[@]}" "${COUNCIL_ARGS[@]}" \
  --proposal "$CHARTER_DRAFT" --proposal-sha256 "$CHARTER_DRAFT_PIN" \
  --old-root-private "$OLD_ROOT_PRIVATE" --output "$CHARTER_SIGNED"
```

**旧根遗失后**，先由新根在旧根无法再签的情况下独立准备并签发 EC267 新 epoch 治理。新治理必须用旧治理**完整文件** SHA 作 predecessor，并保持原 revocation 清单（包括退役源角色签名指纹）。完成后：

```bash
RECOVERY_BASIS=(
  "${OLD_ARGS[@]}" "${COUNCIL_ARGS[@]}"
  --charter "$CHARTER_SIGNED" --charter-sha256 "$CHARTER_SIGNED_PIN"
  --governance-policy "$NEW_GOV" --governance-policy-sha256 "$NEW_GOV_PIN"
  --governance-public "$NEW_ROOT_PUBLIC" --governance-public-sha256 "$NEW_ROOT_PIN"
)
python3 -I -B construction/ec269_emergency_recovery_host/serve.py prepare-recovery \
  "${RECOVERY_BASIS[@]}" --output "$RECOVERY_DRAFT"

# 根签：所输入 SHA 是该 *阶段* 独立确认的完整文件指纹。
python3 -I -B construction/ec269_emergency_recovery_host/serve.py sign-recovery \
  "${RECOVERY_BASIS[@]}" --input-path "$RECOVERY_DRAFT" \
  --input-sha256 "$RECOVERY_DRAFT_PIN" --role new \
  --signing-key "$NEW_ROOT_PRIVATE" --expected-public-sha256 "$NEW_ROOT_PIN" \
  --output "$RECOVERY_ROOT_SIGNED"

# 任选两名委员，以下分别写入自己的阶段文件；必须按指纹升序。
python3 -I -B construction/ec269_emergency_recovery_host/serve.py sign-recovery \
  "${RECOVERY_BASIS[@]}" --input-path "$RECOVERY_ROOT_SIGNED" \
  --input-sha256 "$RECOVERY_ROOT_SIGNED_PIN" --role council \
  --signing-key "$VOTER_A_PRIVATE" --expected-public-sha256 "$VOTER_A_PIN" \
  --output "$RECOVERY_ONE_VOTE"
python3 -I -B construction/ec269_emergency_recovery_host/serve.py sign-recovery \
  "${RECOVERY_BASIS[@]}" --input-path "$RECOVERY_ONE_VOTE" \
  --input-sha256 "$RECOVERY_ONE_VOTE_PIN" --role council \
  --signing-key "$VOTER_B_PRIVATE" --expected-public-sha256 "$VOTER_B_PIN" \
  --output "$RECOVERY_COMPLETE"
```

每一步执行结果含输出 SHA，但**服务准入的固定 SHA 必须由操作员在独立通道确认**。最终必需 `RECOVERY_COMPLETE_PIN`。严禁用已经签名或包含权威密钥的源目录充当信任存储。

## 3. 严格准入

先执行只读 `verify-gate`，再在相同显式参数基础上调用 `serve`。下面是完整的参数形态（变量均须由前述独立持有人给出）：

```bash
HOST_BASIS=(
  "${RECOVERY_BASIS[@]}"
  --recovery-certificate "$RECOVERY_COMPLETE"
  --recovery-certificate-sha256 "$RECOVERY_COMPLETE_PIN"
  --chain "$AUDIT_CHAIN" --chain-sha256 "$AUDIT_CHAIN_PIN"
  --custody-gate "$CUSTODY_GATE" --custody-gate-sha256 "$CUSTODY_GATE_PIN"
  --provenance-gate "$EC266_SOURCE_GATE"
  --provenance-gate-sha256 "$EC266_SOURCE_GATE_PIN"
  --policy "$EC253_POLICY" --repo "$GIT_REPO"
  --allowlist "$ALLOWLIST" --receipt "$SOURCE_RECEIPT"
  --profile-id "$PROFILE_ID"
  --minimum-governance-epoch "$RECOVERED_EPOCH"
  --expected-previous-governance-sha256 "$OLD_GOV_PIN"
)
python3 -I -B construction/ec269_emergency_recovery_host/serve.py \
  verify-gate "${HOST_BASIS[@]}"
python3 -I -B construction/ec269_emergency_recovery_host/serve.py \
  serve "${HOST_BASIS[@]}" --socket "$PRIVATE_SOCKET" --max-sessions 1
```

若当前治理不再是恢复锚 N+1，而是新根后续 epoch，除了替换 `--governance-policy`/SHA 为**当前**治理，还应加 `--anchor-governance`/SHA（仍指向已恢复 N+1）、`--continuation-chain`/SHA（EC268 `prepare-continuation` 的完整配置），同时把独立 `--expected-previous-governance-sha256` 改成续签链的**直接前序**完整文件 SHA。恢复证书、已签章程、历史根公钥和三人委员会公钥保持不变。

## 4. 明确未验证/不支持

- 2-of-3 意味着三枚不同的 Ed25519 **公钥**和两个私钥一致的签名，**不等于两名现实人员或物理设备独立**。本地测试的全部签署者均在同一台开发机模拟。
- 自述的旧根“遗失原因”、事先签署时间、操作员手动 SHA Pin、真实远端 forge/reviewer/CI 与治理角色的合法授权均**不能由密码学自动证明**。本轮未提供离线网络可信时间、HSM、不可回滚的跨重启 epoch、远程 WORM 或真实 Podman/cgroup 验收。
- **如果旧根从未签发恢复章程、章程失效/撤销、三人中不足两人、旧根历史签名文件丢失、或者缺少新的治理根私钥，本路径一律拒绝，不允许无条件重置。**旧根被攻破而非遗失的仲裁、真实人员撤销及章程委员会重组也不在本轮承诺中。
- 单独的恢复章程**不会延长 EC267 ≤24h 当前新治理的有效性**，且本紧急入口的章程超过自身 90 天上限后不能继续服务；后续正式迁移需要另行审批。
- 原 PowerShell V4.60/R150，Router V5.53/R243 74 路由/11 `HOST_REQUIRED`，EC186/187/EC268 原入口均未改变。EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、整体联合验收 `NOT_STARTED`。

本轮局部测试见 [`construction/EC269_LOCAL_REPORT.json`](../construction/EC269_LOCAL_REPORT.json) 和 [`EC-269.md`](../EC-269.md)。这些仅是**施工开发验证**，不是系统级 Quality PASS。
