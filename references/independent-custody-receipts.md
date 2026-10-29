# EC265 — 已签名审计档案的独立保管交接与签收门禁（V5.75/R265）

## 适用范围和信任分界

EC265 只接在 **EC264 已封段、已完整签名、已经通过整链 Pin 核验**的审计档案之后。本轮新增独立的操作员命令，不修改原生 CLI、原 Router、EC186/187 对外协议或旧会话入口。目标是把一个历史封段原样交给其他保管主体，在保管方实际复核并落盘后获得**不同 Ed25519 密钥**签署的交接回执，并由新的严格会话入口逐段要求回执。

这不是云端 API、WORM 驱动、可信时间戳或审计事实真实性认证。`receipt.json` 仅说明某个签名主体声明完成了一次特定字节的落盘签收；**不证明物理上独立的机器、之后不会删除、存储持续在线、运营保留期或所在机房位置**。本地开发时签名方与宿主同机，正式独立性须最终现场验证。

## 真正新增的代码入口

`construction/custody_receipt_host/serve.py` 支持：

| 命令 | 所在安全域 | 完成的实际动作 |
|---|---|---|
| `export-archive` | 停机或隔离的源宿主 | 先校验完整 EC264 链，再把指定已封段导出为固定文件集 |
| `custody-keygen` | 独立保管方的私有机器 | 生成与原 EC263/264 审计签名不同的 Ed25519 密钥对 |
| `receive-archive` | 独立保管方 | 校验来源签名与人工固定的 Pin，落盘并复核后签发回执 |
| `verify-deposit` | 独立保管方 | 重新读取当前保管目录中的归档字节与已签名回执 |
| `verify-custody-gate` | 源宿主 | 验证全部历史封段与相应回执、当前未签段；仅返回 `partial/2` |
| `serve` | 新的 opt-in 严格会话宿主 | 要求完整签收链后才建立会话，受保护审计追加前重新核验 |

源导出目录严格为以下文件：`events.jsonl`、`head.json`、`checkpoint.json`、`continuation.json`、`signer.pub`、`manifest.json`；若档案序号大于 0，还包含 `genesis.json`。不允许多余文件、重名、非私有目录、符号链接、硬链接复用或静默覆盖。

特别注意：**绝不导出** `audit_key`、EC253 双 HMAC、Ed25519 私钥、活动段的尚未签名后缀、会话票据或源码。审计事件本身含运行标识、时间与会话标签，仍可能属于受限元数据；传输媒介、保管权限与离线交换过程必须按业务隐私规则管理。

## 1. 源宿主：从可信完整链导出一个历史封段

前提是 EC264 链配置、签名公钥、每段检查点 SHA、每段续段许可 SHA 和整份链配置 SHA 已通过**独立可信渠道**审核并固定，目标档案已停止写入、完整 EC263 签名且归入 EC264 `archives`。目标导出目录**不存在**，其父目录是操作员持有的 `0700` 私有目录。

```bash
python3 construction/custody_receipt_host/serve.py export-archive \
  --chain /operator/private/chain.json \
  --chain-sha256 <64-hex-chain-pin> \
  --archive-index 0 \
  --output-dir /operator/transfer/archive00
```

工具在 EC264 对源 `events.jsonl` 持有独占锁的情况下核验整链，再从已锁定 FD 流式复制原 journal；固定大小的小文件用安全私有读取，输出文件用 `0600` 新建，先写/同步文件再写正规 `manifest.json`，结束前重新核验源链与导出包。导出命令不会自动压缩、上传、迁移、删除或重写原归档。

打印的 `bundle_manifest_sha256` 是内容标识，**不能替代**已经独立固定的 EC263 检查点、EC264 续段和父许可 Pin；保存它并用独立渠道交给保管方。对于第一个档案，父许可固定值为 64 个字符 `0`；后续必须是相邻上一段续段许可文件的 SHA256。`--archive-index` 从 0 开始，最多 7。

## 2. 独立保管方：生成签名密钥并交接

正式部署要求独立的保管操作系统身份、物理设备和可靠签名密钥保存位置。开发示例只说明参数，不代表已经证明机器隔离。所有私有目录为 `0700`、文件为单链接 `0600`，保管方应通过另一条可靠渠道确认来源 signer SHA、checkpoint SHA、continuation SHA、父许可 SHA、序号及保管方公钥 SHA。

```bash
# 仅在保管方机器执行；严禁将私钥回传源宿主：
python3 construction/custody_receipt_host/serve.py custody-keygen \
  --signing-key /custody/private/custodian-ed25519.key \
  --public-key /custody/private/custodian-ed25519.pub

# 独立确认所有 expected-* 参数后，接收人工传送来的私有文件目录：
python3 construction/custody_receipt_host/serve.py receive-archive \
  --bundle-dir /custody/incoming/archive00 \
  --vault-root /custody/vault \
  --custody-signing-key /custody/private/custodian-ed25519.key \
  --custody-public-sha256 <64-hex-custodian-pub> \
  --archive-index 0 \
  --expected-checkpoint-sha256 <64-hex-source-checkpoint> \
  --expected-continuation-sha256 <64-hex-source-continuation> \
  --expected-parent-continuation-sha256 <64-hex-parent-or-all-zero> \
  --expected-signer-public-sha256 <64-hex-source-offline-signer>
```

`receive-archive` 不持有源宿主 HMAC，因此无法独立重算每条 HMAC；它实际执行的是 Ed25519 来源签名、逐字节 journal SHA、记录数量、末 MAC、`head` 元数据、许可父子关系、已知完整原档案清单与人工提供的精确 Pin 校验。源端完整 HMAC/head 验证仍由 EC264 完成。

成功后会在 `vault-root/<64-hex-manifest-sha>/` 建立**不可复用**的私有目录，采用 `O_EXCL + fsync` 存入档案、重新打开落盘字节核验，再签署 `receipt.json`。该 64 位摘要也是返回的 `deposit_id`。已存在目录或崩溃后留下的不完整目录一律不自动清理/覆盖，应由操作员人工隔离审查。该不可覆盖特性不是针对 root/同 UID 的真正 WORM。

回传给源宿主的只有**完整 `receipt.json` 文件**、保管方 32 字节 Ed25519 公钥（以私有权限保存）和经外部批准的公钥/回执 SHA。保管方私钥不得传送给在线服务。

## 3. 保管方：重新确认当前档案还在

在回执签出后、移交给源宿主前或例行维护时，可通过 `verify-deposit` 重新读取当前存储并核对回执签名：

```bash
python3 construction/custody_receipt_host/serve.py verify-deposit \
  --vault-root /custody/vault \
  --deposit-id <64-hex-bundle-manifest-sha> \
  --custody-public-key /custody/private/custodian-ed25519.pub \
  --custody-public-sha256 <64-hex-custodian-pub> \
  --receipt-sha256 <64-hex-signed-receipt> \
  --archive-index 0 \
  --expected-checkpoint-sha256 <64-hex-source-checkpoint> \
  --expected-continuation-sha256 <64-hex-source-continuation> \
  --expected-parent-continuation-sha256 <64-hex-parent-or-all-zero> \
  --expected-signer-public-sha256 <64-hex-source-offline-signer>
```

输出的 `deposit_bytes_present_and_match_at_check=true` **只表示检查当下的落盘字节与回执一致**。该命令不建立时钟信任、不保证下一秒依然存在、不自动验证外部 object-lock/retention 策略。

## 4. 源宿主：要求每一个旧封段都有独立签收回执

将独立保管方发回的签收原始字节复制到**源宿主的私有操作员配置目录**，固定回执完整 SHA256 和保管方公钥 SHA。每个历史封段对应一份回执；档案必须按 `archive_index=0,1,...` 完整连续，不能跳过中段。

新 `custody-gate.json` 示例：

```json
{
  "schema": "ces.ec265.pinned_custody_gate_config.v1",
  "custody_public_key": "/operator/private/custodian.pub",
  "custody_public_sha256": "<64-hex-custodian-pub>",
  "receipts": [
    {
      "archive_index": 0,
      "receipt": "/operator/private/receipt-00.json",
      "receipt_sha256": "<64-hex-signed-receipt>"
    }
  ]
}
```

以上 JSON 只是供阅读的示例；**落盘必须正规化**，即 `json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'`，文件 `0600`，父目录 `0700`。通过独立渠道固定该文件字节 SHA256，再传入 `--custody-gate-sha256`，不能由宿主自动接受新配置的 SHA。旧 EC264 `--chain-sha256` 依然独立存在、仍必须固定。任何签收方公钥和来源 signer 使用同一 SHA、某档缺少回执、回执被替换或内容与实际锁定源档案不符都会拒绝。

```bash
python3 construction/custody_receipt_host/serve.py verify-custody-gate \
  --chain /operator/private/chain.json \
  --chain-sha256 <64-hex-chain-pin> \
  --custody-gate /operator/private/custody-gate.json \
  --custody-gate-sha256 <64-hex-custody-gate-pin>
```

**正式 opt-in 严格宿主**使用上面四个必需参数，另加原 EC264 `serve` 的 `--policy --repo --allowlist --receipt --profile-id --socket` 以及可选会话限制。源码仍继承 EC259 Git/TAR/HMAC、EC260 主动撤权、EC261 有界外发、EC257 内核 cgroup 计量与 EC253–256 清理，不自动启用历史 Router 的 11 个 HOST_REQUIRED 动作。

`CustodyAudit.record()` 每次受保护审计落盘前重新读取**全部**正规签收文件与门禁配置、验证独立保管者 Ed25519、公钥/字节 Pin，并把签收的 `manifest` SHA 与**源端当时仍在校验的完整封段**逐一重建比较。发生错误会将 writer 标记为不可继续写入并触发原服务异常/清理路径，不用错误回执继续放行。运行中的空闲会话不是远端存储的连续健康探测；移除回执至下一次受保护审计追加之间可能没有检查，须在后续现场审查。

每次 EC264 继续封段/换段后，必须先为新增封段完整执行导出、独立接收和签收，再由操作员更新整份链 Pin、签收配置及独立 Pin，之后才启动 EC265 新宿主。**本轮没有自动网络同步或零停机续段。**

## 5. 局部开发事实与最终联合验证清单

本轮实际运行新代码：13 次非 root 文件/签名/双段/篡改拒绝场景 + 2 次真实 Git/AF_UNIX/fork/Lease 严格宿主场景（Podman/cgroup 模拟）。最初的测试发现并修复“签收后保管目录多一份 receipt”导致复核拒绝的问题；修复后 13/13 和 2/2 通过。历史 EC264 的 15 个局部签名分段用例也在测试发现阶段执行并通过。Python 3.13 测试夹具的多线程 fork 仍有既存警告。

留给用户最终统一辅助验证：确实分离的设备、UID/签名保管、物理媒介传送与独立 Pin 审批；真实 WORM/object-lock/保留期及周期性可用性；root/同 UID、恶意保管者与回执撤销/密钥轮换威胁；真实 rootless Podman/systemd delegated cgroup-v2、断电/满盘/8×32MiB 性能、远端 Git/审批/CI、PowerShell7 原 15 Smoke、Windows/macOS、E63–E66 和原 Router/Provider/Cycle 端到端。**EC249 仍未实现所有功能、EC250 仍 BLOCKED、B001 仍 OPEN；不得宣称 Quality PASS 或最终验收成功。**
