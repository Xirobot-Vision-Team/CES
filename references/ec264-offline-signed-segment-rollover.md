# EC264 — 离线授权的审计封段、续段与多段验证（V5.74/R264）

> **范围：** 新的 Linux 非 root 操作员 opt-in 工具与严格会话入口。旧 EC262/263 服务与日志格式、74 Router、11 `HOST_REQUIRED` 拒绝、PowerShell 原 CLI、EC186/187 wire 均不改动。**封段是保留旧目录并进行密码学内容校验的逻辑归档，不是 WORM/不可删文件系统或可信时间戳。**

## 为什么需要这个流程

EC262 单个 `events.jsonl` 只能存 **32 MiB / 65536 事件**，EC263 签名的是某个历史前缀，后缀仍属在线 HMAC。EC264 不在旧文件满额时自动清空、改名、重置计数或在线签名，而要求操作员先停止写入、完整签名全段、离线批准切换、新目录一次性初始化。完整已封段链在启动与每次新段审计前复核。对这些存量文件而言，旧目录就是封存档案；**不得删除、合并或覆盖**。

一段续段必须同时满足：

- 旧段的 EC262 全部 JSONL/HMAC、独立 `head.json`、EC263 Ed25519 检查点已通过；且签名的 `event_count` 与 `journal_prefix_bytes` **等于整个旧段**，不存在未签后缀。
- 一个**新的** Ed25519 离线签名续段许可（`ces.ec264.offline_signed_audit_continuation.v1`）覆盖已封段的检查点文件 SHA、完整审计 SHA/事件数/最后 MAC、上一个续段许可 SHA、下一个 **独立**审计 HMAC 密钥的 SHA、随机段 ID 和独立 nonce。签名使用与 EC263 相同的离线 signer 密钥和独立域标记，不把 signer 私钥提供给在线服务。
- 操作员独立固定当前 **签名公钥 SHA**、每个已封段 **EC263 检查点 SHA**、每条 **EC264 续段许可 SHA**、整份**规范链配置 SHA**。最后的链配置 Pin 在运行时是必需的，无法让服务从可变本地文件自动学习替代 Pin。
- 每个新段使用全新 HMAC key、全新 `0700` 空目录，创建一次性的 `0600 genesis.json + events.jsonl + head.json`。服务读取已存在的当前日志，从不 `O_CREAT` 补救丢失的日志，也不能自动修复意外部分初始化。

## 一次切段的实际操作

### 1. 停旧服务、完成最后一条审计并离线签名**全段**

把旧 EC262、EC263 或上一轮 EC264 严格宿主**真正停机并确认退出**，在日志接近上限前预留 `service_closed` 和清理事件容量。原 EC263 工具可以签任意已经停止、带合法 HMAC/head 的非空 EC262 段：

```bash
python3 construction/ec263_offline_anchor_host/serve.py propose-checkpoint \
  --audit-root /operator/audit-seg00 --audit-key /operator/private/audit00.key \
  --signer-public-sha256 <64-hex-independently-pinned-signer-sha> \
  --output /operator/private/cp00-proposal.json

# 在独立离线签名环境，审核并签名，留下原始文件和独立 SHA 记录：
python3 construction/ec263_offline_anchor_host/serve.py offline-sign \
  --proposal /offline/private/cp00-proposal.json \
  --signing-key /offline/private/offline-ed25519.key \
  --output /offline/private/cp00-signed.json
```

以上两台机器的独立性在开发环境**没有**验证；旧段签名不自动证明日志事件真实，也不证明远端 Git、审批或容器是真的。签名后不得再启动旧服务追加旧段。

### 2. 创建新的操作员私有 HMAC key 与空目录

```bash
install -d -m 0700 /operator/audit-seg01
python3 - <<'PY'
import os
path = '/operator/private/audit01.key'  # Parent already operator-private 0700
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(fd, 'wb', closefd=False) as f:
        f.write(os.urandom(32)); f.flush(); os.fsync(f.fileno())
finally:
    os.close(fd)
PY
```

新的 32 字节密钥必须与过去每一段的审计 HMAC key **字节不同**、路径不同，不得复用 EC253 原双 HMAC、在线审计 key 或 Ed25519 私钥。将新空目录作为操作员保管的持久目录，放在 OCI scratch/ledger/runtime/repo **外面**。

### 3. 在当前宿主制作 **未授权**续段提案

```bash
python3 construction/ec264_segmented_audit_host/serve.py propose-transition \
  --archive-root /operator/audit-seg00 \
  --archive-key /operator/private/audit00.key \
  --checkpoint /operator/private/cp00-signed.json \
  --checkpoint-sha256 <64-hex-cp00-sha> \
  --signer-public-key /operator/private/offline-signer.pub \
  --signer-public-sha256 <64-hex-signer-sha> \
  --successor-key /operator/private/audit01.key \
  --parent-continuation-sha256 <64-hex-previous-continuation-or-64-zeros-for-FIRST> \
  --output /operator/private/transition00-proposal.json
```

`propose-transition` **持有旧文件锁**并复核签名完整覆盖，然后输出只含摘要/计数/随机标识的 0600 规范提案，不返回旧日志正文、宿主 HMAC 或签名私钥。上一个 permit 的 digest 不会由这个命令自行证明：**必须由离线审查者与真实此前链固定记录核对**。第一次 EC263 → EC264 续段时 `--parent-continuation-sha256` 应是 **64 个 ASCII `0`**；后续必须是紧邻上一 permit 的**独立固定 SHA256**。

### 4. 离线审核并签名续段许可

```bash
# 仅在离线签名环境：
python3 construction/ec264_segmented_audit_host/serve.py offline-sign-transition \
  --proposal /offline/private/transition00-proposal.json \
  --signing-key /offline/private/offline-ed25519.key \
  --output /offline/private/transition00-signed.json
```

离线审核**必须核对**上一段 signed cp pin、精确 SHA/事件数/MAC、前一条 transition SHA、下一段独立 HMAC key 指纹、nonce 和段 ID。许可文件和 signer 公钥以受控渠道传回在线宿主，私钥严禁回传。离线工具生成的 `continuation_sha256` 必须由独立服务配置固定，不能让一个可写本地文件取代运营批准。

### 5. 制作链配置并独立固定其字节 SHA

`chain.json` 是**操作员私有配置**，路径和密钥引用都由宿主可信配置决定，客户端无法传入；务必使用 `0700` 父目录、`0600` 普通文件，**无末尾多余空格或空行**。JSON 必须采用 `sort_keys=True,separators=(',',':'),ensure_ascii=True` 写入且以一个 `\n` 结束。样例（换掉所有尖括号占位值）：

```json
{
  "schema": "ces.ec264.audit_segment_chain_config.v1",
  "signer_public_key": "/operator/private/offline-signer.pub",
  "signer_public_sha256": "<64-hex-signer-sha>",
  "archives": [
    {
      "audit_root": "/operator/audit-seg00",
      "audit_key": "/operator/private/audit00.key",
      "checkpoint": "/operator/private/cp00-signed.json",
      "checkpoint_sha256": "<64-hex-cp00-sha>",
      "continuation": "/operator/private/transition00-signed.json",
      "continuation_sha256": "<64-hex-transition00-sha>"
    }
  ],
  "active": {
    "audit_root": "/operator/audit-seg01",
    "audit_key": "/operator/private/audit01.key",
    "segment_id": "<32-hex-next-segment-id-from-offline-proposal>"
  }
}
```

实际需要按上述排序规则转换为规范 JSON 并一次性创建 0600 文件。`sha256sum /operator/private/chain01.json` 对应其**确切文件字节**；通过独立渠道固定 `--chain-sha256`。**每次滚动必须使用一份新的链配置与新 Pin，不允许覆盖在用的 chain.json**。到下一轮，把原 `active` 变为第二条 `archives`，连同它的最新完整 cp 和新签 transition；在 `active` 填写下一段的信息。原始第一条 archive 不得删掉。最多 8 个已封段（加 1 当前段），超过边界拒绝，不自动剪枝。

### 6. 一次性初始化、只读检查、再启用新严格宿主

```bash
python3 construction/ec264_segmented_audit_host/serve.py init-next \
  --chain /operator/private/chain01.json \
  --chain-sha256 <64-hex-out-of-band-chain-sha>

python3 construction/ec264_segmented_audit_host/serve.py verify-chain \
  --chain /operator/private/chain01.json \
  --chain-sha256 <64-hex-out-of-band-chain-sha>

python3 construction/ec264_segmented_audit_host/serve.py serve \
  --chain /operator/private/chain01.json \
  --chain-sha256 <64-hex-out-of-band-chain-sha> \
  --policy /operator/private/policy.json \
  --repo /operator/repo \
  --allowlist /operator/private/approved-source.json \
  --receipt /operator/private/source.custody.json \
  --profile-id python.pytest --socket /operator/socket/ces264.sock \
  --max-sessions 1 --accept-timeout 60
```

`init-next` **只成功一次**：它检查整条旧链后，在空目录创建 genesis/HMAC 空头，再以只读方式验证。若中途崩溃，目录会留下残件；**不可运行 init 再试，也不可删除残件自动修复**，保留快照并经人工独立审查后重新申请授权。`verify-chain` 全程只读、不会创造日志。两者成功也只回 `status=partial` / **退出码 2**，代表有限本地证据，不是 Quality PASS。签名、Pin/格式、头、链接、权限、同密钥、缺档、未签尾任一不符返回 `unavailable` / **退出码 5**。

新服务仍使用现有 EC259 本地 Git→TAR/HMAC 证明、EC260 活跃撤权、EC261 有界外发、EC257 cgroup/内核水位以及 EC253～256 持久清理。每次受保护审计追加前再次检查**全部已签档案**、完整转场链与当前 HMAC/head；当前段缺失时不重建。旧段使用只读 FD 和独占锁，运行新段时旧服务不能并发打开旧档案写入。

## 安全/性能/验收边界

- **链不断档**是依赖全部旧档案可读取且每段均已签名的逻辑保证，不能阻止同 UID/root 删除文件使系统停机，也不能阻止恶意操作者故意恢复旧配置/旧许可。签名从不认证历史操作的现实真实性。新活动段在下一次停机签名前仍由本地 HMAC 管理，同密钥攻击者在服务停止后可重写未签的活动段；不能称为端到端不可篡改。
- 每次审计都散列**所有已封历史段**（至多 8 × 32 MiB）且重新验证当前段 HMAC；这是有界但昂贵的安全优先实现。**延迟/吞吐、1 秒名义撤权周期、磁盘突发、硬断电、NFS、系统关闭在接近上限时的事件配额**须在真实设备测量；没有建立硬实时保证。该流程要求**预先停机并离线签发许可**，不自动零停机滚动。
- 本地开发测试中签名者与宿主仍在一台机器；集成真实 Git/AF_UNIX/fork/Lease/私有文件，使用**模拟的 Podman/cgroup**。现场要分别验证离线签名机、文件保管、真 rootless Podman/systemd delegated cgroup v2、强制进程树回收、远端 Git/审批/CI/Provider、PowerShell7 原 15 Smoke、E63–E66、Windows/macOS 与用户联验。EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`，11 个原 Router `HOST_REQUIRED` 仍拒绝。
