# EC315 — 跨交付批次的有界追加式 CAS 原签证据历史

**交付版本：V6.25 / R315 / EC315。** 本协议仅核验**已提交给验证器的签名声明的有限历史相容性**；它不会验证物理 CAS/WORM 实际提交、CAS 唯一线性化、全球最新、组织签名公钥授权、可信 UTC/nonce 生成和独立托管。它**不增加新的有效签名或业务权限**。

## 1. 与 EC314 的实质性区别

EC314 同时接收 3–6 份 EC312 原签 observer 窗口并检查一次全图。EC315 把这份工作变成可跨多轮交付的**真实追加式历史**：1–4 份独立整原字节 SHA 钉住的 *delivery* 文件，首批 3–6 个 EC312 窗口，每批后继新增 1–3 个，全部 3–12 个窗口；每个原 EC312 manifest 继续受其自己独立 SHA 钉住。每一个批次都提供前一批完整原 SHA 和从**真实重新核验原件**计算的前缀承诺。不是拿 EC314/EC312 的 JSON 报告或 `PASS` 布尔值做真签来源。

每次核验 **重新读取并执行全部旧批次和最新批次** 的 EC312→EC309→EC308→EC307→EC294 真实 Ed25519/原始 ZIP/ACK/HMAC 等已有验证链。每个追加批次结束都独立重算 EC314 全图的实际已签 issuer/observer 声明、同 revision 异 head、同 signer 同序号不同签名原件、observer 已签前驱、nonce 重用、CAS 父版本/head 连续性；若本批至少一个新窗口不能经**同一份真正原签 EC308 issuer receipt 全文件 SHA**与旧批相接，报 `exit=2`。一个历史前缀失败，即使之后加入窗口让最终图看似连通，也永久 `exit=2`，候选头为 `null`：不能用“后补”抹去曾经无证据或矛盾的历史。

这是面向原件验签的**有限、非加密签发的新账本**。新 delivery 的 SHA 只提供**操作者独立保存的字节承诺**，并不是新的机构 Ed25519 批次签名。只有操作员将上次 `(delivery raw-SHA, verified-originals commitment)` 真正保存在新包外的独立可信地方，并在 `verify-append` 时**明确传给验证器**，才可以在所给范围内检查旧前缀未被替换；验证器不会从新包内自动推断那个包外事实。

## 2. 私有输入及最小格式

使用**目录及其祖先所有者权限合格、无 symlink** 的绝对路径。每个 JSON 文件必须用原协议的**单一规范 JSON、末尾单 LF、0600/0700、单硬链接、完整原字节 SHA-256** 保存。配置私有目录后保持外部 SHA 独立记录。可用旧 EC295 writer `operator.store` 或其它能产生同样规范字节和 owner-private 权限的工具写入。

根 manifest：

```json
{
  "schema": "ces.ec315.signed_cas_delivery_ledger_manifest.v1",
  "cas_authority_id": "<trusted-issuer-id>",
  "cas_authority_public_hex": "<trusted-issuer-ed25519-public-hex>",
  "cas_store_namespace_id": "<external-namespace-id>",
  "expected_registry_id": "<external-registry-id>",
  "deliveries": [
    {
      "sequence": 1,
      "delivery_file": "/owner-private/evidence/delivery-01.json",
      "expected_delivery_sha256": "<independently-recorded-64-lowercase-hex>"
    }
  ]
}
```

首批 `delivery-01.json`（`windows` 至少三项，按 `window_id` 字典序）：

```json
{
  "schema": "ces.ec315.signed_cas_delivery_entry.v1",
  "sequence": 1,
  "previous_delivery_sha256": "GENESIS",
  "previous_verified_originals_commitment_sha256": "GENESIS",
  "windows": [
    {
      "window_id": "window_01",
      "manifest_file": "/owner-private/evidence/original-ec312-a.json",
      "expected_manifest_sha256": "<independent-whole-original-sha>"
    },
    {
      "window_id": "window_02",
      "manifest_file": "/owner-private/evidence/original-ec312-b.json",
      "expected_manifest_sha256": "<independent-whole-original-sha>"
    },
    {
      "window_id": "window_03",
      "manifest_file": "/owner-private/evidence/original-ec312-c.json",
      "expected_manifest_sha256": "<independent-whole-original-sha>"
    }
  ]
}
```

每份原 EC312 窗口自身仍必须有**2–8 份不同原签 issuer 决议和两个独立 observer 原签子链**，完全按 EC312 自身协议。EC315 不创建、修改或代替那些真实 Ed25519 原件。

后继 delivery 使用 `sequence=2`，填入**此前整份 delivery-01.json 原字节 SHA** 和**以前一轮原件重放得到的 `checkpoint_cumulative_replayed_originals_commitment_sha256`**；只列出新窗口。再更新根的 `deliveries` 为 `[第一批原引用, 第二批新引用]`，**不能删除、改写之前元素**。第三、第四批以此类推，每批独立保存整个 JSON 文件的 SHA 并固定之前的链。

承诺算法：规范 JSON（sorted keys、紧凑无空格、末尾 LF）SHA-256；正文含 domain `ces.ec315.verified_original_delivery_prefix_commitment.v1`、根中机关/公钥/namespace/registry、已核验批次序号及每批完整 SHA，和按序每一窗口的原 EC312 manifest 原 SHA、由**实际重放**原签证据导出的 issuer receipt 及 observer readback 整原字节 SHA 集合。没有机器绝对路径、非签名 `PASS` 或密钥。

## 3. 实际命令

```bash
# 完整核验第一批；两枚返回的 checkpoint SHA 必须单独保存。
python -B scripts/ces_cas_ledger.py verify \
  --manifest-file /owner-private/evidence/root-v1.json \
  --expected-manifest-sha256 "<root-v1-external-sha>"

# 第二/三/四批：除新根 SHA 外，必须提供上次在包外保存的两枚检查点。
python -B scripts/ces_cas_ledger.py verify-append \
  --manifest-file /owner-private/evidence/root-v2.json \
  --expected-manifest-sha256 "<root-v2-external-sha>" \
  --expected-prior-delivery-sha256 "<externally-frozen-last-delivery-sha>" \
  --expected-prior-originals-commitment-sha256 "<externally-frozen-previous-verified-source-commitment>"

# 可选：verify 或 verify-append 增加 --out，只可在 owner-private 新路径独占生成 0600/fsync 审计。
# 用外部记录的整个 audit 文件 SHA 另一次重放，不相信报告内自称的 PASS。
python -B scripts/ces_cas_ledger.py verify-report \
  --manifest-file /owner-private/evidence/root-v2.json \
  --expected-manifest-sha256 "<root-v2-external-sha>" \
  --expected-prior-delivery-sha256 "<externally-frozen-last-delivery-sha>" \
  --expected-prior-originals-commitment-sha256 "<externally-frozen-previous-source-commitment>" \
  --audit-report-file /owner-private/evidence/audit-v2.json \
  --expected-audit-report-sha256 "<independent-audit-whole-file-sha>"

# 统一控制台只运行固定隔离只读子进程（不接受 --out/签发/网络/CAS写）。
python -B scripts/ces_next.py audit-ledger DeliveryAudit VerifySignedCasDeliveryLedger \
  --manifest-file /owner-private/evidence/root-v2.json \
  --expected-manifest-sha256 "<root-v2-external-sha>" \
  --expected-prior-delivery-sha256 "<externally-frozen-last-delivery-sha>" \
  --expected-prior-originals-commitment-sha256 "<externally-frozen-previous-source-commitment>"
```

**退出码：** `0` = 本次提交的**全部前缀**互相兼容（仅代表有限原签声明）；`2` = 任意前缀中已有真实签名冲突/不连通/跨批没有原件桥/真父版本断裂，**没有获选 head**；`3` = 不可信权限/外部检查点不相容/安全边界拒绝；`4` = 无效输入或批次结构；`5` = 读源或重放不可用。错误 PIN、伪造签名、改写旧 delivery/窗口或审计、重复 window ID 或原件 SHA、跳号、超预算都拒绝。没有任何命令能对 CAS/Host/Provider 写入。

## 4. 一致性不等于外部历史事实

- `verify` 支持 genesis、也支持全链重验，但**不声称**之前的 checkpoint 已在用户独立可信设施封存；想核对上轮存档，必须用 `verify-append` 并提供真实包外冻结值。
- `verify-append` 只能证明**所给**原 SHA 和原件承诺是否与重新重放的旧前缀相等；不能证明操作员没有重写一个新世界并把新 pin 自己称为旧 pin。它也不证明旧物理 ZIP/ACK/WORM 真正安全存储、公众节点已见证、组织有权使用对应公钥。
- 旧 EC249 仍 incomplete、EC250 仍 BLOCKED、B001 OPEN、Quality PASS=false。原 Router 74/11 默认权限边界、原 PowerShell V4.60/R150 不升级。本机签章 fixture 不能当生产 Provider/Inbox、真实 CAS/WORM、原 PS7 Smoke15、Windows/macOS、CI/E63–E66、跨设备保管和末轮联合验收已完成的证据。
