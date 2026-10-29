# EC275 操作手册：两处独立 EC274 Escrow 的同一签名 Head（Opt-in）

本轮 **V5.85 / R275 / EC275** 只增加一个功能：**同一条 EC274 双见证批准记录，由两处独立 Escrow 签署读回，且在严格 Host 运行期间始终一致**。两个站点完全复用 EC274 已发布 `daemon.py` 的代码和 canonical CAS 协议，新增的只是双站相互独立的受限信任配置、协调推进和新 Host。没有修改原 EC274/273/272 的运行逻辑，也未改原 PowerShell/R150 和 Router/R243。

## 1. 资产、角色与攻击边界

- A 站与 B 站分别运行现成 `construction/remote_escrow_host/daemon.py`，各持**不同**独立 Ed25519 回应签名私钥、**不同** TLS leaf、各自单独签发的 CA/根 bundle、单独的 `0600` journal/进程锁和隔离运维控制域。两站使用**相同**项目 namespace、同一套外部固定的 3 个 witness 公钥、相同的 EC272 根/EC270 closure，签发的 head 必须是**完全一样的 EC274 canonical record bytes**（SHA-256 相等且内容相等）。两站**都不**持有 witness 私钥。
- 三位 offline witnesses 的 2/3 见证签名、完整 EC272 live/历史证据和 EC273 时间戳仍先按 EC274 既有 `prepare-proposal`、`sign-proposal`、`assemble-record` 流程产生**一条**记录；禁止为 A/B 各自重新生成随机 proposal（不同 nonce 导致不同 head）。
- Operator 通过新的 `operator.py` 检查、按固定顺序写 A/B、独立读回。只允许 A/B 当前在 `expected_previous_sha256` 或**该条明确审批的** `record_sha256`；任何站返回第三个 head、分叉、签名故障或网络不可达，**立即停止推进**。并且未完成的 A-only/B-only 写入绝不伪装为双站成功。
- Protected Host 新入口 `serve.py` 继承 EC274 的原有 EC273/272/271/270 认证/保管/审计/Lease/主动撤权；每次检查先真实验证 EC274 主站签名 nonce 回读，再验证独立 B 站签名 nonce 回读。二者均须等于**Host 持有的事先经操作者批准的同一记录 SHA**，并且记录携带的全部 current tail 字段与本机真正验签的 EC272/273 证据吻合。业务 Host **仅可读**，不能调用 advance。

**不可混淆：** 代码内的 `two_sites`、双 CA、双签名是逻辑上的两套证据，不代表实际部署已在两家独立机房，也不是硬件单调计数器/WORM。不论是两站同时恶意回退，还是全部 CA/witness 密钥失陷，均无法由同一机的本地模拟证明真实独立性。两个站点的写入**不是分布式原子事务**；为安全故意停在不一致状态直到人工恢复，而非提供可用性降级。

## 2. 部署两个已有 EC274 daemon（各站独立执行）

各站的命令结构相同；`namespace`、3 witness 公钥和根/closure SHA 必须相同，但 `journal`、独立 escrow 签名私钥/公钥 SHA、TLS CA/leaf/key 和部署机器应**不同**：

```bash
python construction/remote_escrow_host/daemon.py \
  --bind 0.0.0.0 --port 9443 --namespace example-project-a \
  --journal /private/site-A/escrow.jsonl \
  --escrow-secret /private/site-A/escrow-secret.raw \
  --escrow-public-sha256 "$SITE_A_ED25519_PUBLIC_SHA256" \
  --witness-public /private/site-A/witness-1.raw --witness-public-sha256 "$W1_SHA" \
  --witness-public /private/site-A/witness-2.raw --witness-public-sha256 "$W2_SHA" \
  --witness-public /private/site-A/witness-3.raw --witness-public-sha256 "$W3_SHA" \
  --root-sha256 "$ROOT_SHA" --closure-sha256 "$CLOSURE_SHA" \
  --tls-cert /private/site-A/leaf.pem --tls-key /private/site-A/leaf-key.pem \
  --bootstrap-minimum-sequence "$APPROVED_FIRST_SEQUENCE" \
  --bootstrap-minimum-epoch "$APPROVED_FIRST_EPOCH"
```

B 站用**另一个 CA、公钥、证书、journal 和物理节点**启动同一守护程序；切勿将 A 的私钥/当前日志复制给 B。实际专网 TLS、服务防火墙、证书吊销和备份另行依照运营侧审批与验收。

## 3. 先批准「同一条」 signed record，再双站推进

首先从 EC274 既有的 `operator.py prepare-proposal` 完整验证 EC272+273 的证据，offline witness A/B 签名，然后 `assemble-record` 得到一份 canonical `RECORD.json`。**把 record 的完整 SHA-256 和 previous head SHA-256 记入独立审批清单**。本功能不生成/保管 witness 私钥。

新的三个操作动作共有这些参数（示例使用 shell 数组代表原有固定公钥配置；括号中的 token **不是**真实密钥）:

```bash
COMMON=(
  --escrow-host escrow-a.example.net --escrow-port 9443
  --escrow-namespace example-project-a
  --escrow-tls-ca /trust/site-A-ca.pem --escrow-tls-ca-sha256 "$SITE_A_CA_SHA"
  --escrow-tls-leaf-sha256 "$SITE_A_LEAF_DER_SHA"
  --escrow-public /trust/site-A-escrow.raw --escrow-public-sha256 "$SITE_A_ED25519_PUBLIC_SHA256"
  --secondary-escrow-host escrow-b.example.net --secondary-escrow-port 9443
  --secondary-escrow-tls-ca /trust/site-B-ca.pem --secondary-escrow-tls-ca-sha256 "$SITE_B_CA_SHA"
  --secondary-escrow-tls-leaf-sha256 "$SITE_B_LEAF_DER_SHA"
  --secondary-escrow-public /trust/site-B-escrow.raw --secondary-escrow-public-sha256 "$SITE_B_ED25519_PUBLIC_SHA256"
  --root-sha256 "$ROOT_SHA" --closure-sha256 "$CLOSURE_SHA"
  --freshness-witness-public /trust/w1.raw --freshness-witness-public-sha256 "$W1_SHA"
  --freshness-witness-public /trust/w2.raw --freshness-witness-public-sha256 "$W2_SHA"
  --freshness-witness-public /trust/w3.raw --freshness-witness-public-sha256 "$W3_SHA"
)

# A/B 当前分别可为「审批前驱」或「已批准的新记录」。无需写入。
python construction/dual_escrow_host/operator.py inspect-advance \
  "${COMMON[@]}" --record /private/RECORD.json \
  --record-sha256 "$NEW_HEAD" --expected-previous-sha256 "$PREVIOUS_HEAD"

# 在双站预检查通过后固定顺序写 A、读回，再写 B、读回，再双站各自签名读回。
python construction/dual_escrow_host/operator.py advance-dual \
  "${COMMON[@]}" --record /private/RECORD.json \
  --record-sha256 "$NEW_HEAD" --expected-previous-sha256 "$PREVIOUS_HEAD"

# 只读回读（双 nonce/双签名/双完整 head；不负责验证 EC272+273 本机 current tail）。
python construction/dual_escrow_host/operator.py inspect-dual \
  "${COMMON[@]}" --expected-head-sha256 "$NEW_HEAD" --minimum-index 1
```

启动全新双站 journal 时 `$PREVIOUS_HEAD` 必须是 64 个 `0`，签名 record 的 `record_index` 必须为 1。后续为前驱记录**完整 canonical bytes SHA**。`--minimum-index` 需填 operator 审批的当前最小序号；例子 `1` 只适用于首次提交，后续应使用相应更高楼层。

**部分提交修复：** 若 A 成功而 B 失联（或 B 成功而 A 失联），必须先恢复原服务、独立检查两处签名 head，核对批准 SHA，再对**原来的完全相同 RECORD 和 SHA**调用 `inspect-advance` 和 `advance-dual`。程序识别已完成的一侧并仅补齐另一侧。若出现第三个 head，不能跳过 CAS、更不能删除日志或改写 genesis；需人工作原因分析和另行签署治理方案。任何异常只给出失败，不声称双站已同步。

## 4. 严格 Host opt-in

使用新增入口（原 EC274 CLI 参数**全部**仍为必填，且需保证 `--escrow-record-sha256` 已独立审批）：

```bash
python construction/dual_escrow_host/serve.py verify-gate \
  [全部 EC274 verify-gate 的原有参数] \
  --secondary-escrow-host escrow-b.example.net --secondary-escrow-port 9443 \
  --secondary-escrow-tls-ca /trust/site-B-ca.pem \
  --secondary-escrow-tls-ca-sha256 "$SITE_B_CA_SHA" \
  --secondary-escrow-tls-leaf-sha256 "$SITE_B_LEAF_DER_SHA" \
  --secondary-escrow-public /trust/site-B-escrow.raw \
  --secondary-escrow-public-sha256 "$SITE_B_ED25519_PUBLIC_SHA256" \
  --secondary-escrow-minimum-index "$APPROVED_INDEX"
```

`serve` 命令同理；此外保留 EC274 `--socket`/`--max-sessions`/`--accept-timeout`。新 Host 会拒绝两站同签名公钥、同 CA bytes SHA、同 TLS leaf DER SHA、同 endpoint、复用信任文件路径、和三个 witness 公钥重合的 escrow 签名公钥。CA PEM 内容 SHA、leaf DER SHA、raw Ed25519 public SHA、TLS SAN/host、随机 nonce、record 双见证真签章均由各自完整读取校验；不信任未签名的状态缓存。

## 5. 局部验证 vs 最终联合验收

适当的非 root Linux + Python/cryptography/OpenSSL/Git 环境下：

```bash
PYTHONPATH=construction python construction/dual_escrow_host/test_quorum.py
PYTHONPATH=construction python construction/dual_escrow_host/test_host.py
PYTHONPATH=construction python construction/remote_escrow_host/test_escrow.py
PYTHONPATH=construction python construction/remote_escrow_host/test_host.py
```

这些只会在测试代码指定的真实前置条件满足时执行，测试模拟两个 localhost TLS authority、合成 CA/Ed25519 公钥/双见证和真实 Git/socket/Lease/审计/TSA，**OCI/cgroup 在 Host 用例里为 mock**。无法代替：物理上真正独立的操作者/机房及 witness 持有人、跨设施实际两站提交/分区/重启、独立不可变 WORM/HSM/备份后的回读防回退、真实 CA 吊销与轮换、外部可信 TSA、Podman/cgroup、全量原 PowerShell 15 Smoke/Windows/macOS/Router 联合验收。B001、EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED` 和最终用户验收仍未关闭。
