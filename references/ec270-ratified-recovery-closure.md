# EC270 — 紧急治理恢复结案：四阶段见证签署与非临时章程严格宿主

> 对应施工包 **V5.80/R270/EC270**。它只新增 opt-in 入口，不修改 EC269 紧急服务：原服务仍要求章程每次处于有效期内。**结案必须在章程及恢复锚治理 N+1 均有效时完成；不能在到期后凭这一功能补造历史签署。**

## 1. 做到的业务能力

EC269 恢复章程用于事故期间限时授权恢复，但原服务会在最多 90 天的章程窗口结束时拒绝继续。EC270 提供独立的**恢复根正式结案**路径：

1. **输入真实 EC269 已完整签署的恢复历史**：旧根公钥、旧已签 EC267 治理 N、旧根预签的 2-of-3 恢复章程、三个委员会公钥、新根公钥、已签的恢复锚治理 N+1、完整新根签 + 两票 EC269 恢复证书，**每份输入均由操作员独立 SHA256 固定**。不接受单票、未签或未授权旧根“重置”。
2. **新增第四方见证**：独立于旧根、新根、3 名委员、EC266 源签名角色和 EC264/265 审计保管签名人的新 Ed25519 公钥。先由恢复新根签署同一份结案声明，再由两名**按公钥 SHA 升序**的已预授权委员签署，最后**独立见证者签整份已签署文件及其观察时间**。签署期间 EC269 章程和 N+1 锚治理必须仍有效，任何步骤必须额外提供并核验**前一步完整文件 SHA**；所有输出都只可新建，不覆写、不附带私钥。见证者在离线签署端自读墙钟并签名，不接受调用者提供任意时间。
3. **结案后新的专用宿主** `ec270_recovery_closure_host/serve.py` 在 socket、新租约、`service_start` 前以及每次 begin、活动会话中复核旧/新根签名、历史章程、旧恢复证书、四签结案证书、累计撤销、当前 EC267 <=24h 治理、源 Git/TAR/角色签章、EC265 离线保管、EC264 审计、EC253 HMAC/租约与 EC257/260/261 资源和撤权。历史章程仍必须**存在且内容有效**，但不再要求其**今天尚未过期**。可继续通过原 EC268 的最多 32 条、逐份独立固定 SHA 的新根签治理链，直到需要另行授权新的锚。
4. **额外防倒退**：启动必须单独给出完整结案 SHA、**最小治理 epoch** 和**最小见证观察时间**，从本地 EC267 时钟/单进程单调时间拒绝明显“未来观察时间”；根、委员、见证人若成为新治理的来源角色或出现在后续撤销清单中则拒绝；丢失/改写任何历史凭据仍拒绝并走原 Lease/cgroup 清理。

## 2. 操作顺序

在 `ces/` 根目录执行（示例变量均指**运营方独立确认的真实文件路径与完整 SHA**，不要直接相信 CLI 自己打印的 SHA 作为外部审批或信任根）：

```bash
python3 -I -B construction/ec270_recovery_closure_host/serve.py --help
python3 -I -B construction/ec270_recovery_closure_host/serve.py prepare-closure --help

# 旧签章程、旧已签治理、紧急恢复证书等必须保留至服务期满之后。
COUNCIL=(
  --council-public "$COUNCIL_1_PUB" --council-public-sha256 "$COUNCIL_1_PIN"
  --council-public "$COUNCIL_2_PUB" --council-public-sha256 "$COUNCIL_2_PIN"
  --council-public "$COUNCIL_3_PUB" --council-public-sha256 "$COUNCIL_3_PIN"
)
CLOSURE_BASIS=(
  --old-governance "$OLD_GOV" --old-governance-sha256 "$OLD_GOV_SHA"
  --old-root-public "$OLD_ROOT_PUB" --old-root-public-sha256 "$OLD_ROOT_PIN"
  --charter "$SIGNED_CHARTER" --charter-sha256 "$CHARTER_SHA"
  --recovery-certificate "$SIGNED_RECOVERY" --recovery-certificate-sha256 "$RECOVERY_SHA"
  --anchor-governance "$RECOVERED_N_PLUS_1_GOV" --anchor-governance-sha256 "$ANCHOR_SHA"
  --governance-public "$RECOVERED_ROOT_PUB" --governance-public-sha256 "$RECOVERED_ROOT_PIN"
  --witness-public "$INDEPENDENT_WITNESS_PUB" --witness-public-sha256 "$WITNESS_PIN"
  "${COUNCIL[@]}"
)

# 必须在章程有效且 N+1 锚治理尚未到期时完成全部四次签署。
python3 -I -B construction/ec270_recovery_closure_host/serve.py prepare-closure \
  "${CLOSURE_BASIS[@]}" --output "$CLOSURE_DRAFT"

# CLOSURE_DRAFT_SHA 要求独立复核完整 draft 文件后才填写。
python3 -I -B construction/ec270_recovery_closure_host/serve.py sign-closure \
  "${CLOSURE_BASIS[@]}" --input-path "$CLOSURE_DRAFT" \
  --input-sha256 "$CLOSURE_DRAFT_SHA" --role root \
  --signing-key "$RECOVERED_ROOT_PRIVATE" --expected-public-sha256 "$RECOVERED_ROOT_PIN" \
  --output "$CLOSURE_ROOT_STAGE"

# 委员的 SHA 必须选严格升序的两位；示例中的 A、B 表示已排好序者。
python3 -I -B construction/ec270_recovery_closure_host/serve.py sign-closure \
  "${CLOSURE_BASIS[@]}" --input-path "$CLOSURE_ROOT_STAGE" \
  --input-sha256 "$ROOT_STAGE_SHA" --role council \
  --signing-key "$COUNCIL_A_PRIVATE" --expected-public-sha256 "$COUNCIL_A_PIN" \
  --output "$CLOSURE_ONE_VOTE"
python3 -I -B construction/ec270_recovery_closure_host/serve.py sign-closure \
  "${CLOSURE_BASIS[@]}" --input-path "$CLOSURE_ONE_VOTE" \
  --input-sha256 "$ONE_VOTE_SHA" --role council \
  --signing-key "$COUNCIL_B_PRIVATE" --expected-public-sha256 "$COUNCIL_B_PIN" \
  --output "$CLOSURE_TWO_VOTES"

# 见证端复核此前所有字节并以自己的时钟读取观察时间；这是第四个独立私钥。
python3 -I -B construction/ec270_recovery_closure_host/serve.py sign-closure \
  "${CLOSURE_BASIS[@]}" --input-path "$CLOSURE_TWO_VOTES" \
  --input-sha256 "$TWO_VOTES_SHA" --role witness \
  --signing-key "$WITNESS_PRIVATE" --expected-public-sha256 "$WITNESS_PIN" \
  --output "$CLOSURE_FINAL_CERT"

# 签名者独立封存并复核 CLOSURE_FINAL_SHA，再投入新宿主。
python3 -I -B construction/ec270_recovery_closure_host/serve.py verify-closure \
  "${CLOSURE_BASIS[@]}" --closure-certificate "$CLOSURE_FINAL_CERT" \
  --closure-certificate-sha256 "$CLOSURE_FINAL_SHA"
```

**特别注意：** `prepare-closure` 和 `sign-closure` 的 `--anchor-governance` **必须是最初获批准的 EC269 恢复锚 N+1**，不接受第二天的治理文件取代原结案凭证。N+1 一旦过期而结案尚未完成，本轮的结案路径就会拒绝；请按正式独立治理事故程序处置，不得修改旧文件绕过。

## 3. 恢复结案后的严格服务

```bash
# 当前是原 N+1 时：CURRENT_GOV = RECOVERED_N_PLUS_1_GOV，CURRENT_SHA = ANCHOR_SHA，
# CURRENT_PREDECESSOR_SHA = OLD_GOV_SHA，MIN_EPOCH = N+1，且不传续签链。
# 当前是 N+2 或以后时：使用现行签治理 CURRENT_GOV / CURRENT_SHA，
# 完整的 EC268 continuation-chain + 独立 SHA，最小 epoch 与直接前序 SHA。
HOST_BASIS=(
  "${CLOSURE_BASIS[@]}"
  --closure-certificate "$CLOSURE_FINAL_CERT"
  --closure-certificate-sha256 "$CLOSURE_FINAL_SHA"
  --minimum-closure-observed-at-unix "$INDEPENDENT_MIN_WITNESS_UNIX"
  --governance-policy "$CURRENT_GOV" --governance-policy-sha256 "$CURRENT_SHA"
  --minimum-governance-epoch "$MIN_EPOCH"
  --expected-previous-governance-sha256 "$CURRENT_PREDECESSOR_SHA"
  --chain "$AUDIT_CHAIN" --chain-sha256 "$AUDIT_CHAIN_PIN"
  --custody-gate "$CUSTODY_GATE" --custody-gate-sha256 "$CUSTODY_GATE_PIN"
  --provenance-gate "$SOURCE_PROVENANCE_GATE" --provenance-gate-sha256 "$SOURCE_GATE_PIN"
  --policy "$LEASE_POLICY" --repo "$GIT_REPO" --allowlist "$ALLOWLIST"
  --receipt "$SOURCE_RECEIPT" --profile-id "$PROFILE_ID"
)
python3 -I -B construction/ec270_recovery_closure_host/serve.py verify-gate "${HOST_BASIS[@]}"
python3 -I -B construction/ec270_recovery_closure_host/serve.py serve \
  "${HOST_BASIS[@]}" --socket "$PRIVATE_SOCKET" --max-sessions 1
```

如果是 N+2 之后，请在上面的 `HOST_BASIS` 追加 `--continuation-chain "$CHAIN" --continuation-chain-sha256 "$CHAIN_SHA"`。运营方至少单独保管**恢复证书、结案证书、历史公钥和已签治理完整原件**，以及见证人独立核对的观察时间下界；服务不会自动收集信任材料或自动升高运营锚。只有 `verify-gate`/`serve` 接受公钥和已签材料，**不接受任何四类签署私钥**。返回 `partial/2` 仅代表本地部分证明符合要求，**不是质量验收 PASS**。

## 4. 信任与验证边界

- **独立见证只是签名身份和该签名者对时间的声明。** 代码可以验证见证密钥签过的时间在历史章程和锚治理窗口内，也可拒绝本地时间看来“未来”的签署，但不能证明实际 UTC、防操作员跨重启回滚本地时间/所有 SHA/epoch Pin、四名签署人确系不同组织/自然人。见证私钥串通或见证钟被回拨时，声明可以被伪造。因此在生产环境需要**独立可信时间/不可回滚保管**与见证者法律/业务授权独立审批。
- **只豁免历史章程的“当前有效期”**，绝不豁免其签名、完整哈希、旧根持有的历史公钥、两票恢复证书、后续撤销和当前 EC267 治理签名/到期；任何有一项材料缺失或不匹配，一律 fail closed。EC269 旧独立服务不变，不自动升级。
- 无法替代真实远端 Git forge/reviewer/CI 身份事实、物理 WORM、受委托的真实 Linux Podman/cgroup v2 全树停止、PowerShell7 原 15 Smoke、Windows/macOS/E63–E66、原 Router 11 HOST_REQUIRED 及用户最终联合验收。原 EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN` 保留。

开发范围与局部实测见 [`EC-270.md`](../EC-270.md)、[`construction/EC270_SCOPE.json`](../construction/EC270_SCOPE.json)、[`construction/EC270_LOCAL_REPORT.json`](../construction/EC270_LOCAL_REPORT.json)。
