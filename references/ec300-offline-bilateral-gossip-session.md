# EC300 离线双见证共签会话与跨轮回退核对｜操作手册

版本 **V6.10/R300**。本模块**不连接网络、不负责私钥生成/分配，不提供远端不可回退存储**；与 EC299 相同，所有 `*_file` 必须是可信受限目录下存在的**绝对路径**。每一轮仍需保有两个见证各自的 EC299 完整观察 manifest 和每一观察对应的原 EC297 全套历史、四个外部 SHA pin。

## 一、角色、独立保管与数据结构

- A/B 是两个**不同** Ed25519 公钥和身份标签；分别在安全离线主机持有私钥。`--expected-a-id/--expected-a-public-hex` 等值必须提前从可信带外通道核对，不能以待验 JSON 自证身份。A/B 对**同一份** EC299 比较结果双签；这不代表二人真实不同，也不表示已经收到异地对方消息。
- 每轮操作者另行取得独立的**高熵 challenge** 并将其 SHA-256 摘要转为 **64 个小写 hex 字符**，经独立可信渠道分发并保留原 challenge、摘要和来源的对应关系。字段名 `independent_challenge_sha256` 表示一个**外部已计算的摘要**，程序不会生成随机数、验证挑战来源/可信 UTC，也不把“只是任意 64 位 hex”证明成真实的新鲜挑战。
- 第一次签署 `--sequence 1`，不带 prior history 和 predecessor SHA；后续指定完整上一轮的 `--prior-history-file` + **独立已保存**的 `--expected-previous-session-sha256`，序号必须是此前完整会话数 +1。会话总数 1～8；若需超过八轮，不能悄悄截断旧轮以冒充完整新进度。
- 每一个“历史条目”的 `expected_session_sha256`、`expected_a_tip`、`expected_b_tip` 都是**从可信来源抄入**的核验 pin；本地 JSON 值不能凭空证明独立保管。

历史 manifest 严格 JSON 格式，所有文件路径均为现存绝对路径，示意：

```json
{
  "schema": "ces.ec300.bilateral_gossip_full_history.v1",
  "a_id": "site_alpha",
  "a_public_hex": "<A 公钥 64 小写 hex>",
  "b_id": "site_beta",
  "b_public_hex": "<B 公钥 64 小写 hex>",
  "sessions": [
    {
      "signed_session_file": "/private/round1-signed-session.json",
      "expected_session_sha256": "<外部确认的第 1 轮完整 SHA>",
      "witness_manifest_file": "/private/round1-ec299-manifest.json",
      "expected_a_tip": "<第 1 轮 A 的已签观察 tip>",
      "expected_b_tip": "<第 1 轮 B 的已签观察 tip>"
    }
  ]
}
```

每轮签完只向这个历史 manifest **追加**新一轮条目，并保留全部旧签名会话文件及每轮的原 EC299 manifest/原始审计证据。禁止只保留末端摘要作“完整历史”。如果涉及异机迁移，只能调整上述本地来源**路径**，不能改任何原始字节、独立 pin 或 Ed25519 票据。

## 二、离线四步骤

第一个命令从**本轮** EC299 witness manifest 和两枚独立观察 tip、身份/公钥、会话序号、挑战开始；**第 2～8 轮**还必须携带上述 `--prior-history-file` 和 `--expected-previous-session-sha256`，签署双方应事先通过可信渠道核对旧 session tip。

```bash
# Bash：本轮所有 prepare/sign/assemble 复用完全相同的参数。
COMMON=(
  --witness-manifest-file /private/current-ec299-manifest.json
  --expected-a-id site_alpha --expected-a-public-hex "$A_PUBLIC"
  --expected-a-tip "$A_TIP"
  --expected-b-id site_beta --expected-b-public-hex "$B_PUBLIC"
  --expected-b-tip "$B_TIP"
  --sequence 1 --independent-challenge-sha256 "$CHALLENGE_SHA256"
)
# 序号 >=2 时，在 COMMON 内另外加入完整的前史：
# --prior-history-file /private/previous-full-history.json
# --expected-previous-session-sha256 "$PREVIOUS_SESSION_SHA"
python3 -I -B scripts/ces_anchor_gossip.py prepare-session \
  "${COMMON[@]}" --out /private/round1-proposal.json
```

从 JSON 输出取得 `proposal_sha256`，经独立渠道核对后，**每位密钥持有者**携带与上面**完全相同**的会话参数，在自己的离线环境重验完整原始证据、提案 hash、公钥与对应私钥，分别签 A 和 B 的 EC300 角色票：

```bash
python3 -I -B scripts/ces_anchor_gossip.py sign-session \
  "${COMMON[@]}" --proposal-file /private/round1-proposal.json \
  --expected-proposal-sha256 "$PROPOSAL_SHA" \
  --role a --private-key-file /private/a.key \
  --out /private/round1-a-vote.json

# B 的另一台设备以同样完整参数执行：
# --role b --private-key-file /private/b.key
# --out /private/round1-b-vote.json
# 私钥始终不应随投递材料共享；分别进行签署动作。
```

签署程序从不签任意外来 Claim：先验 SHA、重算当前 EC299 所有真实历史及原 EC298 竞争分支，再核对上一轮**完整**已签会话及新增真实历史前缀。汇总时再重算相同声明，然后校验各自 `vote_..._sha256`、公钥和双签：

```bash
python3 -I -B scripts/ces_anchor_gossip.py assemble-session \
  "${COMMON[@]}" \
  --proposal-file /private/round1-proposal.json \
  --expected-proposal-sha256 "$PROPOSAL_SHA" \
  --vote-a-file /private/round1-a-vote.json \
  --expected-vote-a-sha256 "$A_VOTE_SHA" \
  --vote-b-file /private/round1-b-vote.json \
  --expected-vote-b-sha256 "$B_VOTE_SHA" \
  --out /private/round1-signed-session.json
```

记录 `signed_session_sha256` 到可信外部通道；生成下一次会话前，把上一轮已签 session 加入完整 history manifest。所有输出创建均 `0600` + 独占 `O_EXCL` + 文件和目录 fsync，已存在文件**拒绝覆盖**。中途失败可能留有 unsigned proposal 或 one-side vote，**不代表共签成功**。

## 三、独立复验与比对结果

验证者须独立得到最新完整 signed session SHA、A/B 观察 tip、身份和公钥，且读取完整 1～N 轮会话来源。示意：

```bash
python3 -I -B scripts/ces_anchor_gossip.py verify-history \
  --history-file /private/full-ec300-history.json \
  --expected-session-tip "$SESSION_TIP" \
  --expected-a-id site_alpha --expected-a-public-hex "$A_PUBLIC" \
  --expected-a-tip "$A_TIP" \
  --expected-b-id site_beta --expected-b-public-hex "$B_PUBLIC" \
  --expected-b-tip "$B_TIP" \
  --out /private/verification-report.json

# 若另有独立保存的整份 report SHA，还可用 verify-report。
# 重复 verify-history 的 8 个必填校验参数（不带 --out），并附加：
python3 -I -B scripts/ces_anchor_gossip.py verify-report \
  --history-file /private/full-ec300-history.json \
  --expected-session-tip "$SESSION_TIP" \
  --expected-a-id site_alpha --expected-a-public-hex "$A_PUBLIC" \
  --expected-a-tip "$A_TIP" \
  --expected-b-id site_beta --expected-b-public-hex "$B_PUBLIC" \
  --expected-b-tip "$B_TIP" \
  --report-file /private/verification-report.json \
  --expected-report-sha256 "$EXTERNALLY_RETAINED_REPORT_SHA"
```

精确只读统一控制台：

```bash
python3 -I -B scripts/ces_next.py audit-gossip DeliveryAudit VerifyGossip \
  --history-file /private/full-ec300-history.json \
  --expected-session-tip "$SESSION_TIP" \
  --expected-a-id site_alpha --expected-a-public-hex "$A_PUBLIC" \
  --expected-a-tip "$A_TIP" \
  --expected-b-id site_beta --expected-b-public-hex "$B_PUBLIC" \
  --expected-b-tip "$B_TIP"
```

**结果语义：** `0` = 所**提供的**历史相容；`2` = 原真实签名竞争或至少一个历史配对无法证明有序；`3/4/5` = 权限/输入/环境不满足，不提供成功结论。任何较早会话的 fork/inconclusive 不能被后续报告“清白化”。会话链是 **signed evidence**，不是自行完成的双站发信、活体证明或外部存储保障。

## 四、终验预留（不在本地自动声称成功）

两名真实独立管理人各自保有独立 challenge 提供者、最新 A/B 已签观察 tip、最新会话 tip 和报告 SHA；确认另一设备/站点是否真实收到和落到不可回退存储、权限/备份/密钥撤销、可信时间和断电后 fsync 恢复。还需生产 Provider/Inbox/TLS、完整原始 PowerShell7 15 Smoke、Windows/macOS/Git/CI/E63～E66 及整体原 EC249/250 终验。权限边界和 Quality PASS=false 不变。
