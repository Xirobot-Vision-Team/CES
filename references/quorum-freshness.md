# EC271 — 恢复结案后独立双见证短时效凭据、连续 SHA 链与严格宿主

> 代码施工包 **CES V5.81/R271/EC271 FULL**。本轮**只新增独立 opt-in 组件**，原 EC270 已结案恢复宿主、EC269 章程到期拒绝和 EC268/EC267/EC266–EC253 老入口及 Native PowerShell / Router 均保持原样。**本功能实际执行签名与核验，但不能单靠本地签章证明远端独立人员、可信 UTC 或跨重启不可回滚。**

## 1. 真实可调用的增量能力

EC270 对旧根历史恢复完成合法四签结案，可以在旧章程到期后继续使用新根已签 EC267 治理；但当前治理只以 EC267 最多 24 小时窗口和操作员自己的 epoch/pin 防回滚。EC271 在其**外面额外加一道必须显式选择的短时效见证门**：

- 每份 `ces.ec271.two_of_three_fresh_governance_seal.v1` 绑定：完整历史 EC270 结案证书 SHA、当前恢复根公钥 SHA、当前 EC267 已签治理 SHA 与 epoch、见证者固定三人公钥 SHA 集、连续 `sequence` / `previous_receipt_sha256`、15 分钟以内窗口和随机 nonce。
- 三名名单成员中 **任意两名按公钥 SHA 严格升序**签署；签名使用新的域分离 Ed25519 消息，第二人还要将第一人完整签名和所见 Unix 秒数签入消息。见证间观察时间最多相差 120 秒，且时间严格处于批准窗口；不允许重复签名、改投或冒充旧根/新根、委员会、EC270 原见证、已撤销 EC267 源角色、EC264/265 签收/审计角色。
- 每次 `prepare-freshness`、每次 `sign-freshness` 重新核验整条 EC270 历史旧根/委员会/恢复根/结案四签和**所有 EC268 恢复根续签治理 epoch**、所有见证者公钥 SHA、上一份已达双签的独立 SHA，以及当前签治理有效期边界。每个阶段都以 `O_EXCL` 新建 canonical JSON 私有文件，旧证据不可被覆盖。
- `append-chain` 重新读回并核验**全部旧双签收据**后增添一份双签新收据；链配置只追加 `receipt_path/receipt_sha256` 严格有界表，整个配置另需独立 SHA 固定。单轮最多 **256** 张凭据，避免无限信任路径及校验开销；到上限**拒绝**，不静默丢弃老历史。要继续超出上限必须另行设计签名锚分段/认可的滚动移交，不准擅自截掉链头充当新 `sequence=1`。
- 新 `freshness_quorum_host/serve.py verify-gate/serve` 是**唯一**使用双见证凭据的新 opt-in 严格服务。先跑完整 EC270 当前治理、完整旧恢复/结案证据、EC266 Git/TAR 三角色、EC265 离线签收、EC264 HMAC/签名审计、EC253 HMAC/Lease、EC257/260/261 OCI/cgroup 与主动撤权，再逐张校验全部双见证链。只有最后凭据的 epoch/治理 SHA 恰好等于当前治理、符合 `--minimum-freshness-sequence` 和独立 `--expected-previous-receipt-sha256`、并在本机当前/单调时钟认可的短窗口内，才允许 `service_start`、socket、新会话。
- 在 `begin` / 运行中 session guard / 拒绝慢读外发期间，每次重读完整凭据链和见证者公钥；历史文件丢失、改写、签名吊销、过期或与新治理不相符时全部失败关闭，继承 EC260/261 原会话撤权、Lease 清偿及 OCI 清理，不补发已失败的响应。

## 2. 命令与输出（所有变量均由操作员独立确认）

切换至 `ces/` 根目录：

```bash
python3 -I -B construction/freshness_quorum_host/serve.py --help
python3 -I -B construction/freshness_quorum_host/serve.py prepare-freshness --help
```

先定义 EC270 的完整历史输入。`$HISTORY_ARGS` 表示下面 Bash 数组，而**非实际 CLI 单一开关**：

```bash
HISTORY_ARGS=(
  --old-governance "$OLD_GOV" --old-governance-sha256 "$OLD_GOV_SHA"
  --old-root-public "$OLD_ROOT_PUB" --old-root-public-sha256 "$OLD_ROOT_PIN"
  --charter "$OLD_SIGNED_CHARTER" --charter-sha256 "$CHARTER_PIN"
  --anchor-governance "$RECOVERED_N_PLUS_ONE_GOV" --anchor-governance-sha256 "$ANCHOR_PIN"
  --governance-public "$RECOVERED_ROOT_PUB" --governance-public-sha256 "$RECOVERED_ROOT_PIN"
  --recovery-certificate "$RECOVERY_CERT" --recovery-certificate-sha256 "$RECOVERY_PIN"
  --witness-public "$EC270_WITNESS_PUB" --witness-public-sha256 "$EC270_WITNESS_PIN"
  --closure-certificate "$EC270_CLOSURE" --closure-certificate-sha256 "$EC270_CLOSURE_PIN"
  --council-public "$COUNCIL_A_PUB" --council-public-sha256 "$COUNCIL_A_PIN"
  --council-public "$COUNCIL_B_PUB" --council-public-sha256 "$COUNCIL_B_PIN"
  --council-public "$COUNCIL_C_PUB" --council-public-sha256 "$COUNCIL_C_PIN"
)
FRESH_WITNESSES=(
  --freshness-witness-public "$FRESH_WITNESS_A_PUB" --freshness-witness-public-sha256 "$FRESH_WITNESS_A_PIN"
  --freshness-witness-public "$FRESH_WITNESS_B_PUB" --freshness-witness-public-sha256 "$FRESH_WITNESS_B_PIN"
  --freshness-witness-public "$FRESH_WITNESS_C_PUB" --freshness-witness-public-sha256 "$FRESH_WITNESS_C_PIN"
)
CURRENT=(
  --governance-policy "$CURRENT_SIGNED_GOV" --governance-policy-sha256 "$CURRENT_GOV_PIN"
)
# 如果当前是恢复锚 N+2 或更后，三组命令都额外带上：
# --continuation-chain "$EC268_CONTINUATION" --continuation-chain-sha256 "$CONTINUATION_SHA"
# 如已知独立已签保管/审计角色，请在离线命令中增加多个 --forbidden-public-sha256 <SHA>。
```

首次签署与配置（时刻是 Unix 秒，`END - START <= 900`，且两者均位于当前已签 EC267 治理窗口内）：

```bash
python3 -I -B construction/freshness_quorum_host/serve.py prepare-freshness \
  "${HISTORY_ARGS[@]}" "${FRESH_WITNESSES[@]}" "${CURRENT[@]}" \
  --sequence 1 --not-before-unix "$START" --expires-at-unix "$END" \
  --output "$FRESH_DRAFT"

# FIRST_PIN 和 SECOND_PIN 必须对应已选两名名单成员，按公钥 SHA 升序；
# *_SHA 必须经离线操作员独立核对文件的完整 SHA 后填入。
python3 -I -B construction/freshness_quorum_host/serve.py sign-freshness \
  "${HISTORY_ARGS[@]}" "${FRESH_WITNESSES[@]}" "${CURRENT[@]}" \
  --input-path "$FRESH_DRAFT" --input-sha256 "$DRAFT_SHA" \
  --signing-key "$FIRST_SIGNER_SECRET" --expected-public-sha256 "$FIRST_PIN" \
  --output "$FRESH_FIRST_SIGNED"
python3 -I -B construction/freshness_quorum_host/serve.py sign-freshness \
  "${HISTORY_ARGS[@]}" "${FRESH_WITNESSES[@]}" "${CURRENT[@]}" \
  --input-path "$FRESH_FIRST_SIGNED" --input-sha256 "$FIRST_STAGE_SHA" \
  --signing-key "$SECOND_SIGNER_SECRET" --expected-public-sha256 "$SECOND_PIN" \
  --output "$FRESH_QUORUM_SIGNED"
python3 -I -B construction/freshness_quorum_host/serve.py append-chain \
  "${FRESH_WITNESSES[@]}" --receipt "$FRESH_QUORUM_SIGNED" \
  --receipt-sha256 "$FRESH_QUORUM_SHA" --output "$FRESH_CHAIN"
```

**续签** `sequence=2` 且明确传上一份签章文件和其独立 SHA：

```bash
# 三次 prepare/sign 都加：
# --previous-receipt "$LAST_SIGNED_RECEIPT" --previous-receipt-sha256 "$LAST_RECEIPT_SHA"
# --sequence 2; 窗口起点不得早于上一份最后一名见证者签署时刻。
# 当前 EC267 governance 更换 epoch，则还须给出新的 CURRENT 与完整续签链。
python3 -I -B construction/freshness_quorum_host/serve.py append-chain \
  "${FRESH_WITNESSES[@]}" --receipt "$NEXT_QUORUM_SIGNED" \
  --receipt-sha256 "$NEXT_RECEIPT_SHA" \
  --previous-chain "$FRESH_CHAIN" --previous-chain-sha256 "$FRESH_CHAIN_SHA" \
  --output "$FRESH_CHAIN_2"
```

在 `verify-gate` / `serve` 上沿用 EC270 的所有严格宿主入参（参见 [EC270 宿主配置](ratified-recovery-closure.md)），**另外必需**：

```bash
--freshness-witness-public "$FRESH_WITNESS_A_PUB" --freshness-witness-public-sha256 "$FRESH_WITNESS_A_PIN"
--freshness-witness-public "$FRESH_WITNESS_B_PUB" --freshness-witness-public-sha256 "$FRESH_WITNESS_B_PIN"
--freshness-witness-public "$FRESH_WITNESS_C_PUB" --freshness-witness-public-sha256 "$FRESH_WITNESS_C_PIN"
--freshness-chain "$FRESH_CHAIN" --freshness-chain-sha256 "$FRESH_CHAIN_SHA"
--minimum-freshness-sequence 1 --expected-previous-receipt-sha256 0000000000000000000000000000000000000000000000000000000000000000
```

从第 2 张起，上述前序 SHA 为倒数第二张完整收据的外部独立 Pin。续签生效需要使用新链配置 SHA 重启这一独立宿主，**运行中替换配置不是热更新授权**；旧宿主在旧凭据过期时拒绝并撤销活动会话。新服务器从不接收 `--signing-key` 参数，也不会在服务中自动生成任何新证书。离线 `verify-chain` 命令可检查签名及到期情况，但既不能冒充全套 EC265 宿主与远端授权，也不能代替完整的 `verify-gate`。

## 3. 不能夸大的验证边界

- 验证两份签名只表示**持有这两个 Ed25519 私钥的一方签署了同一主张**，不证明其分别是独立人员、在独立设施，或受法律/组织授权。见证者所见 Unix 时间是被签名的声明；两名串通或时钟共同回拨，仍可共同说谎。
- 代码不连接外部 NTP/TSA 或远端不可回滚保管服务，不实现真实跨重启 monotonic floor。CLI 的 `--minimum-freshness-sequence`、前序收据 SHA 及整个 chain SHA 需要**由真正独立的操作员/外部封存系统独立保存并递增**。同一人随意修改所有 Pin 仍可能重放旧链。
- 因证书最多 15 分钟，停发新凭据后旧独立宿主会**主动过期拒绝**；没有默许离线豁免。每条链最多 256 张，容量耗尽前应启动独立审批的后续协议设计，绝不能只删除旧收据后谎称连续。
- 本次本地真实 Git/AF_UNIX/Lease、两密钥签名、审计文件和主动撤权用例仅证明开发环境行为；未执行真正外部独立证人、真实 WORM、rootless Podman/systemd delegated cgroup v2、完整 PowerShell 15 Smoke、Windows/macOS/E63–E66 或最终联合验收。EC249、EC250、B001 历史状态不变。
