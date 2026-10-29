# EC268 — 离线三方治理根密钥交接及新根独立续签

本说明适用于 **单独 opt-in 的 EC268 严格宿主**，不是对原 PowerShell、Router 或原 EC267 的隐式升级。代码：[`handover.py`](../construction/root_handover_host/handover.py)、[`serve.py`](../construction/root_handover_host/serve.py)。

## 一、要补的缺口与精确信任边界

EC267 已验证独立第四方签署的短期治理文件、三名来源签发者密钥和累计撤销名单，但仅将一个治理根公钥的 SHA 固定在本地：**它不知道旧根交给新根是否真的有旧根授权、新根持钥证明，以及独立见证同意**。EC268 添加三份 Ed25519 **不同域**签名的同一张规范 JSON 根交接证书：先 `old`、后 `new`、最后 `witness`。旧根和新根各自都必须在各自独立 Pin 下验证前后两张 EC267 治理文件；见证根公钥必须与这两根及前后全部 `origin/review/ci` 角色、EC264 审计、EC265 保管签发者独立。三次签名在不同步骤由不同的离线方完成，每一步要求上一步**完整字节独立 SHA Pin**，生成新文件，不覆写旧文件。

交接要求：旧治理 epoch = N、新治理 epoch = N+1；新治理 `previous_governance_sha256` 必须等于旧文件完整 SHA；旧治理撤销名单被新治理包含；若 `origin/review/ci` 任一旧密钥不再是新活动角色，必须**显式放进新撤销清单**。旧文件只需证明历史签发有效，即使已过期仍可供新根交接追溯；**新文件必须继续通过 EC267 的当前时间、角色、来源、epoch floor、前序独立 Pin 验证**。

证书永远记录的是历史交接，不是独立时间戳。要让旧根真正退役，EC268 另外提供单独 Pin 的、最多 **32 次后续 epoch** 的规范治理续签链。初次交接证书固定的是 epoch N+1 的「锚治理文件」；后续 epoch N+2、N+3…可仅由**新根私钥**签发，严格宿主重验链内全部 Ed25519 签名、epoch +1、上一完整 SHA、累计撤销及被替代角色的撤销；每次重新固定整份续签链 SHA 和当前治理 SHA，保留最初交接证书。这使旧根和见证方的私钥无需继续在线或为每次 24h 续签重新签名。

**绝不能把这说成无需额外信任的跨重启防回滚**：最低 epoch、当前治理 Pin、续签链 Pin、三个公钥 Pin、最初签名证书 Pin 等必须由独立操作员/外部根维护并在服务配置中更新。拥有全部本机文件/配置权限的人仍能回滚一整套配置，系统时钟可被管理员修改；旧根私钥已丢失时，不支持单方应急恢复。真实远端身份、源提供方、可信时间、签署机物理隔离或硬件签发都需要用户最终验证。

## 二、文件形状与签名对象

签名的**无签名负载**严格包含且仅包含：

```json
{
  "schema": "ces.ec268.three_party_governance_root_handover.v1",
  "old_governance_sha256": "<sha-of-old-signed-ec267>",
  "new_governance_sha256": "<sha-of-anchor-signed-ec267>",
  "old_root_public_sha256": "<sha-of-old-32-byte-ed25519-public>",
  "new_root_public_sha256": "<sha-of-new-32-byte-ed25519-public>",
  "witness_public_sha256": "<sha-of-independent-witness-32-byte-public>",
  "old_epoch": 1,
  "new_epoch": 2,
  "declared_at_unix": 1792882800,
  "nonce": "<32-lowercase-hex>"
}
```

`declared_at_unix` 是签发方的**自述**，不是可信时间证明。所有 SHA 都是小写 64 十六进制；示例中的尖括号是文字占位符，不是合法入参。真正的编码是原 EC266 `prov._canonical`（规范 JSON 加末尾换行）。三个签名分别放入 `signature_old_ed25519`、`signature_new_ed25519`、`signature_witness_ed25519`，编码均为 128 个小写十六进制字符。签名消息：

```
CES/EC268/governance-root-handover/v1\0 + ROLE_ASCII + \0 + CANONICAL_UNSIGNED_JSON
```

**签名次序固定**，任何缺项、多项、跳过、插入未知字段、非规范 JSON、替换文件、非活动根、同一密钥多角色、错误前序 SHA、签名伪造都拒绝。交接证书和参与签名的三个公钥/两份 EC267 签名文件以及所有续签链文件必须离开 source Git、审计根和原三角色证据目录。

续签链（仅发生后续 epoch 时需要）是完整规范 JSON，操作者单独固定全文件 SHA：

```json
{
  "schema": "ces.ec268.pinned_new_root_governance_continuation.v1",
  "entries": [
    {
      "governance_policy": "/private/epoch3.signed.json",
      "governance_policy_sha256": "<sha-of-epoch3>"
    },
    {
      "governance_policy": "/private/epoch4.signed.json",
      "governance_policy_sha256": "<sha-of-epoch4>"
    }
  ]
}
```

锚治理文件不在 `entries` 内，它由 `--anchor-governance` 固定；entries 依序为其后的 epoch，最后一条必须精确匹配 `--governance-policy`。链上最多 32 个后续节点。不可直接跳过旧文档、替换先前 chain、让已撤销公钥重新成为签发者或重用旧路径。

## 三、分机、分人准备及三签名步骤

以下 `PIN_*` 都必须是**操作者通过独立可信渠道确认的真实 SHA**。单纯从被验证的待签名文件中复制其自报 SHA 无效。使用私有目录（0700）及权限 0600 的新文件；不要把签发私钥放到 `verify-gate` 或 `serve` 主机。原 EC267 的 `governance-keygen` 可在独立离线终端生成新根和见证方密钥。先分别构建旧根签发的 epoch N 与新根签发的 epoch N+1 两张 EC267 治理文件，正确继承撤销记录并更新签发者源门禁；两张原文件均不覆写。

1. 使用另一台规划/交接审核设备创建**尚无任何交接签名**的 proposal：

```bash
python3 construction/root_handover_host/serve.py prepare-handover \
  --previous-governance-policy /private/epoch1.signed.json \
  --previous-governance-policy-sha256 PIN_OLD_GOV \
  --previous-governance-public /private/old-root.pub \
  --previous-governance-public-sha256 PIN_OLD_ROOT \
  --governance-policy /private/epoch2.signed.json \
  --governance-policy-sha256 PIN_ANCHOR_GOV \
  --governance-public /private/new-root.pub \
  --governance-public-sha256 PIN_NEW_ROOT \
  --witness-public /private/witness.pub \
  --witness-public-sha256 PIN_WITNESS \
  --output /private/handover.proposal.json
```

2. 旧根**独立审阅完整新旧治理文件、撤销历史和新根身份**，使用自己私钥签署上步 proposal 的确切文件 SHA：

```bash
python3 construction/root_handover_host/serve.py sign-offline \
  --role old --input /private/handover.proposal.json \
  --input-sha256 PIN_PROPOSAL --signing-key /offline/old-root.secret \
  --expected-public-sha256 PIN_OLD_ROOT \
  --output /private/handover.old-signed.json
```

3. 新根分别读取、固定、复核 old-signed 文件；先验证**旧根公钥与独立固定的旧根 SHA**，再签自己的证明：

```bash
python3 construction/root_handover_host/serve.py sign-offline \
  --role new --input /private/handover.old-signed.json \
  --input-sha256 PIN_OLD_SIGNED --signing-key /offline/new-root.secret \
  --expected-public-sha256 PIN_NEW_ROOT \
  --previous-governance-public /private/old-root.pub \
  --previous-governance-public-sha256 PIN_OLD_ROOT \
  --output /private/handover.two-signed.json
```

4. 独立见证方同样由独立渠道取得两个签发根公钥和各自 SHA，并复核两个完整签名后完成交接：

```bash
python3 construction/root_handover_host/serve.py sign-offline \
  --role witness --input /private/handover.two-signed.json \
  --input-sha256 PIN_TWO_SIGNED --signing-key /offline/witness.secret \
  --expected-public-sha256 PIN_WITNESS \
  --previous-governance-public /private/old-root.pub \
  --previous-governance-public-sha256 PIN_OLD_ROOT \
  --governance-public /private/new-root.pub \
  --governance-public-sha256 PIN_NEW_ROOT \
  --output /private/handover.three-signed.json
```

所有签发输出都是新建 O_EXCL/0600/fsync 私有文件。三方签完后，操作者**独立固定**最终证书 SHA (`PIN_HANDOVER`)。历史证书和公钥/签名文件长期保留（不等同 WORM）。

## 四、严格宿主调用

进入原 EC265/266/267 已配置的私有宿主环境后，第一次交接 `verify-gate` 必须传入以下标志。用已有 EC267 host 的全部 `--chain --chain-sha256 --custody-gate --custody-gate-sha256 --provenance-gate --provenance-gate-sha256 --policy --repo --allowlist --receipt --profile-id` 等原先**准确值**，再增加：

```bash
python3 construction/root_handover_host/serve.py verify-gate \
  --chain /private/chain.json --chain-sha256 PIN_CHAIN \
  --custody-gate /private/custody-gate.json --custody-gate-sha256 PIN_CUSTODY \
  --provenance-gate /private/source-gate.json --provenance-gate-sha256 PIN_SOURCE \
  --policy /private/ec253-policy.json --repo /private/approved-repo \
  --allowlist /private/allowlist.json --receipt /private/source.custody.json \
  --profile-id python.pytest \
  --previous-governance-policy /private/epoch1.signed.json \
  --previous-governance-policy-sha256 PIN_OLD_GOV \
  --previous-governance-public /private/old-root.pub \
  --previous-governance-public-sha256 PIN_OLD_ROOT \
  --governance-policy /private/epoch2.signed.json \
  --governance-policy-sha256 PIN_ANCHOR_GOV \
  --governance-public /private/new-root.pub \
  --governance-public-sha256 PIN_NEW_ROOT \
  --anchor-governance /private/epoch2.signed.json \
  --anchor-governance-sha256 PIN_ANCHOR_GOV \
  --witness-public /private/witness.pub \
  --witness-public-sha256 PIN_WITNESS \
  --handover-certificate /private/handover.three-signed.json \
  --handover-certificate-sha256 PIN_HANDOVER \
  --minimum-governance-epoch 2 \
  --expected-previous-governance-sha256 PIN_OLD_GOV
```

首次不传 `--continuation-chain`。它只做核验；`serve` 使用**完全相同签名配置**加上 `--socket /private/run/ces.sock --max-sessions 1 --accept-timeout 60`。严格宿主继承原 EC265/EC266/EC267：启动先恢复以前未清理租约；在任何新 socket/租约/`service_start` 审计追加前核验全部来源、治理、旧新签名和交接证书；运行中不断核验，失败拒绝输出并走原 OCI/cgroup 全树清理和审计/ledger 关闭路径。

## 五、只有新根参与后续短期治理续签

**例：**在 epoch 2 有效期内，新根签出 EC267 epoch 3 治理；其 `previous_governance_sha256` 是 epoch2 完整 SHA，撤销名单必须包含 epoch2 的所有撤销记录。创建首个续签链：

```bash
python3 construction/root_handover_host/serve.py prepare-continuation \
  --anchor-governance /private/epoch2.signed.json \
  --anchor-governance-sha256 PIN_ANCHOR_GOV \
  --governance-public /private/new-root.pub \
  --governance-public-sha256 PIN_NEW_ROOT \
  --next-governance /private/epoch3.signed.json \
  --next-governance-sha256 PIN_EPOCH3_GOV \
  --output /private/new-root-chain-to-epoch3.json
```

要增至 epoch 4，仅再让**新根**签出 epoch4 EC267 文件（前序 SHA 为 epoch3），然后同一命令额外指定 `--previous-chain /private/new-root-chain-to-epoch3.json --previous-chain-sha256 PIN_PREVIOUS_CHAIN`，更换 `--next-governance` 指向 epoch4，`--output` 必须是新的非覆盖文件。每轮独立更新新链 SHA、最新治理 SHA、`--minimum-governance-epoch` 以及 `--expected-previous-governance-sha256`（最新治理**直接**前驱的 SHA）。

继续 `verify-gate` / `serve` 时：`--previous-governance-*` 和 `--anchor-governance-*` 以及三个原根/见证公钥 Pin、最初交接证书 Pin **不变**；`--governance-policy*` 指向最新 epoch，`--continuation-chain /private/new-root-chain-to-epochX.json --continuation-chain-sha256 PIN_CHAIN_X`。这条新 strict 服务将核验**锚之后整条续签链**。若链超过 32 节，当前代码**拒绝**（不自动抹掉历史、更不伪称无限回滚保护）；应由另一次经单独授权的信任锚迁移方案解决。

## 六、真实测试、工作量与最终联合验收

EC268 新增局部真实 Linux 非 root Git/HMAC/Ed25519 文件流与签名/文件替换/顺序/交接/旧 CI 撤销/独立续签链的功能用例；新宿主测试真实 Git、AF_UNIX/fork/lease/audit 与运行中撤权清理，**mock Podman/cgroup**。这些测试签发钥匙和证据**全部在同一开发机器**。即使全通过，也不表示已经部署三台物理独立签发设备、外部服务真实性、可信跨重启 epoch/时钟/WORM、真实 rootless Podman/delegated cgroup 或原本所有 PowerShell 15 Smoke/Windows/macOS/E63–E66/11 Router 拒绝/Provider/业务写/Cycle，更不是 `Quality PASS`。最终共同联验由用户统一协助。

`EC249=FULL_FUNCTION_NOT_COMPLETE`、`EC250=BLOCKED`、`B001=OPEN`、最终接受 `NOT_STARTED`，返回保持 `partial/2`，不升级原接口。
