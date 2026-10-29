# EC277 — 双站独立服务端强制双人审批 CAS / 操作者手册

## 解决的具体绕过

EC276 验证了离线签名，但原 EC274 daemon `/v1/advance` 只需两位 *witness* 签署记录；具有网络访问的旧客户端可绕开新的两位 *operator approver* 签名。EC277 是一套**独立选择部署**的新服务端+新客户端协议，要求**两台服务端在写入自己本地不可跨机原子的 EC274 CAS journal 之前**分别验证同一份完整 EC276 批准文件；原服务端和 CLI 文件均不作修改。

部署 EC277 `daemon.py` 时**不再注册** `/v1/advance`，只开放 `/v1/read`（兼容旧只读严格 Host）与 `/v1/advance-approved`。任何旧 `RemoteClient.advance`/EC275 `advance-dual`/EC276 原 `advance-approved` 请求将在这个新服务端被拒绝，而不是自动回落旧协议。服务端签名同时证明**该服务自身经受限授权准入**，但不能证明曾经运行在何种硬件/物理位置。必须确保生产网络只能接入新的 EC277 监听端口，关闭/隔离 EC274 的旧写入口；不能把客户端侧保证当作服务端部署保证。

## 必需信任资料及统一的机器可读配置

每一站及在线 Operator **各自持有一份本地 canonical JSON policy**，对本地 policy 文件做 SHA-256 带外钉住。不同机器上的文件绝对路径可以不同，但 policy 中两站 `host/port/tls_ca_sha256/tls_leaf_sha256/escrow_public_sha256` 必须表达相同的真实站点身份，这些字段将与 EC276 已签授权逐字段对比。所有文件由私有目录保护，不能把私钥放入 operator/Host 或另外一站。一次 JSON 策略结构示意如下（**仅为字段示例**，不是可直接运行的信任证据）：

```json
{
  "schema": "ces.ec277.approval_enforced_escrow_policy.v1",
  "namespace": "ces-production-namespace",
  "recovered_root_public_sha256": "<64-hex-root-public-digest>",
  "closure_sha256": "<64-hex-recovery-closure-digest>",
  "primary": {
    "host": "escrow-a.example.org", "port": 9443,
    "tls_ca": "/trusted/escrow-a-ca.pem",
    "tls_ca_sha256": "<64-hex-raw-PEM-file-digest>",
    "tls_leaf_sha256": "<64-hex-X509-leaf-DER-digest>",
    "escrow_public": "/trusted/escrow-a-ed25519-public.raw",
    "escrow_public_sha256": "<64-hex-raw-Ed25519-public-digest>"
  },
  "secondary": {
    "host": "escrow-b.example.org", "port": 9444,
    "tls_ca": "/trusted/escrow-b-ca.pem",
    "tls_ca_sha256": "<64-hex-raw-PEM-file-digest>",
    "tls_leaf_sha256": "<64-hex-X509-leaf-DER-digest>",
    "escrow_public": "/trusted/escrow-b-ed25519-public.raw",
    "escrow_public_sha256": "<64-hex-raw-Ed25519-public-digest>"
  },
  "witnesses": [
    {"path":"/trusted/witness-1.raw","sha256":"<64-hex-public-digest>"},
    {"path":"/trusted/witness-2.raw","sha256":"<64-hex-public-digest>"},
    {"path":"/trusted/witness-3.raw","sha256":"<64-hex-public-digest>"}
  ],
  "approvers": [
    {"path":"/trusted/approver-1.raw","sha256":"<64-hex-public-digest>"},
    {"path":"/trusted/approver-2.raw","sha256":"<64-hex-public-digest>"},
    {"path":"/trusted/approver-3.raw","sha256":"<64-hex-public-digest>"}
  ]
}
```

使用 EC274 的 `esc.canonical()` 或等价的 **UTF-8、排序键、紧凑格式、末尾一个 LF** 写入，不能手工复制带占位符的示意文件。可信 SHA 来自独立治理渠道，严禁从未经鉴定的配置自身“自动信任”其摘要。三名 witness、三名 approver、治理 root、A/B 两位 escrow signer 都有不同的 SHA-pinned 公钥。两站必须使用不同 CA、leaf、signer、endpoint 与独立日志，EC277 启动时还要校验**本机实际加载的 leaf DER** 等于其 role 在策略中的 pinned 值、端口精确相等；签名私钥由 EC274 原账本代码查验所属 escrow public pin。

## 真实运行入口

前提：已由旧 EC274 witness `prepare-proposal` / `sign-proposal` / `assemble-record` 出具一条完整被两位 witness 签署的下一记录。继续用 EC276 原封不动的 `prepare-intent` / 两位持钥人分别在离线设备执行 `sign-intent` / `assemble-approval` 出具**完全相同的** approval 文件；它绑定单条记录、前驱 SHA、序号、两站 TLS/CA/签名人指纹、3+3 身份和最长 72h 签署窗口。本轮不生成、不读取任何 operator approver 私钥。

两台**分别单独启动**新的 EC277 daemon（此处以 A 为例；B 换 role、port、日志、证书与仅属于 B 的 escrow 私钥）：

```bash
PYTHONPATH=construction python construction/ec277_approval_enforced_escrow/daemon.py \
  --bind 127.0.0.1 --port 9443 --role primary \
  --policy /trusted/escrow-policy-a.json \
  --policy-sha256 "${POLICY_A_SHA256}" \
  --journal /escrow-private/escrow-a-ledger.jsonl \
  --escrow-secret /escrow-private/escrow-a-secret.raw \
  --tls-cert /escrow-private/escrow-a-leaf.pem \
  --tls-key /escrow-private/escrow-a-tls.key \
  --bootstrap-minimum-sequence "${PINNED_BOOTSTRAP_SEQUENCE_FLOOR}" \
  --bootstrap-minimum-epoch "${PINNED_BOOTSTRAP_EPOCH_FLOOR}"
```

`--bind` 仅为示例，应通过部署方独立设置受限监听、网络隔离及 DNS/负载均衡使 `host:port`、SNI、证书 SAN 精确对应。更改证书或 policy 后必须走新信任分发/签署流程，不能绕过 pin 直接热改。历史账本由服务持有 private fd + 单进程 `flock` + `fsync`，不允许自动重置、跳序或换前驱。

执行端使用同样**经过独立钉住**的 public trust 配置；三个操作只接受已完整签署的 EC276 approval 文件：

```bash
PYTHONPATH=construction python construction/ec277_approval_enforced_escrow/operator.py \
  inspect-advance-approved \
  --policy /trusted/operator-escrow-policy.json \
  --policy-sha256 "${OPERATOR_POLICY_SHA256}" \
  --approval /trusted/approved-ec276.json \
  --approval-sha256 "${APPROVAL_SHA256}"

PYTHONPATH=construction python construction/ec277_approval_enforced_escrow/operator.py \
  advance-approved \
  --policy /trusted/operator-escrow-policy.json \
  --policy-sha256 "${OPERATOR_POLICY_SHA256}" \
  --approval /trusted/approved-ec276.json \
  --approval-sha256 "${APPROVAL_SHA256}"

PYTHONPATH=construction python construction/ec277_approval_enforced_escrow/operator.py \
  inspect-approved \
  --policy /trusted/operator-escrow-policy.json \
  --policy-sha256 "${OPERATOR_POLICY_SHA256}" \
  --approval /trusted/approved-ec276.json \
  --approval-sha256 "${APPROVAL_SHA256}"
```

**返回约定**：`exit_code=2` 表示业务证据已验证/部分状态（不是发布通过），`exit_code=5` 表示受限拒绝/不可用；查询不写入。新 `advance-approved` 先双站预读并逐一验证前驱，再按 A/B 顺序发送**完整授权文档**，站点在独立的时间/站点/公钥策略下重验两人投票、记录及角色；所有成功的写返回 (1) 原 EC274 服务器新 nonce 内嵌 signed head，(2) 新 EC277 域分离 Ed25519 **签名准入回执**：`site_role`, `approval_sha256`, `record_sha256`, `record_index`, `admitted_at_unix`, `nonce`, `signed_head`。在线客户端逐字段与原批准文档、站点角色和公钥比较并验签，随后重读本地站点，两站最后再各自签一次 nonce 响应；真实写出的签名 receipt 通过 JSON 输出中的 `new_server_signed_commit_receipts` 提供给操作者保存，不包含审批私钥。

**半提交恢复**：A 已提交而 B 失败时，不应声称成功，也不能删除 A 的日志。独立人工核对两站、权限、变更后，用**同一条 EC276 见证记录**重试，原签名仍在窗口内可以继续；过期后由两位独立 approver 针对**相同完整 record 和两站 pin**重新签发新窗口授权，不能趁恢复替换 record。已写入的一站不会重新执行 CAS；新回执可能只来自本次实际写入的另一站。`inspect-approved` 的两份 signed read 证明当前 head 相等，但**不能反推过去每一条操作都曾经经由 EC277 的强制审批端点**。新 CLI 会明确报告本次实际拿到几个 EC277 signed commit receipts，禁止把已完成的重试声称为“两站本次新批准”。

## 安全边界与最终统一验收

- EC277 的签名 approval 是**有限期的单记录 bearer 能力**；任何拿到该文件的人都能在期限内尝试推进**那一条**已预签记录，不能自动推广到其它记录。签名和服务器当前时间并不证明真实审批人亲自在线，真实人员独立性、网络隔离、保密分发和停权归运营方。
- 现有进程内单调时钟锚仅缓解**当前进程**墙钟回退，不能提供**跨进程重启**的真实 UTC；独立可信时钟、重启不回退锚、HSM/WORM、真实物理分站、运营权限和证书撤销均不在这轮实施范围内。
- 每站只保证自己独立的 EC274 CAS + journal；A/B 不是分布式原子事务，断线、读不出确认、fsync 不确定结果时必须重新读并**拒绝假成功**。
- EC277 **不修改** EC276 严格 Host，其已有 EC275/274 兼容的 `/v1/read` 路径可以用于读取 EC277 daemon 的 signed head；新服务端严格审批只约束**确实已切换到 EC277 daemon 的端点**。旧服务端或旧写端口如仍对外开放，依旧可以成为旁路。
- 本轮的本地 8 个集中测试用 synthetic localhost 双站 TLS/独立签名密钥、实际有效/伪造 approval、journal、CLI、半提交与恢复；无真实受托 CA/人/设备/外部主机隔离的证明。原生 PowerShell7 15 Smoke、Windows/macOS E63–E66、Router 11 HOST_REQUIRED、rootless Podman+cgroup v2、真实 Git forge/CI/审计 WORM、跨机器网络分区及最终统一验收继续累计，**不标全局 Quality PASS**。
