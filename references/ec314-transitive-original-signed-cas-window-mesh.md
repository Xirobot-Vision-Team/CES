# EC314 — 3–6 份独立 CAS 已签观察窗口的原件交集网格（完全只读）

## 目标与严格前提

EC313 只检验**两份** EC312 原签名窗口；本轮 EC314 用 **3–6 份独立 SHA pin 的真实 EC312 私有 manifest** 构建有限图。节点是经原 `EC312.evaluate()` **分别完整重验**的窗口（2–8 条 EC308 CAS issuer 原签裁决、两名 EC309 observer 的每笔 Ed25519 原签回读，逐路重跑 EC307→294 的原签来源）。边**仅**在两节点真正共享**完全相同原 EC308 已签 issuer receipt 的完整原字节 SHA** 时成立；窗口编号、CAS revision 连续、观察者公钥相同、旧审计 JSON `PASS` 都不能代替一条边。允许 A–B、B–C 共享不同原件，而 A–C 没有直接共享原件；必须整个网格连通，不得只验证一个方便的子图。

外部需要独立维护**同一 CAS authority ID/公钥、物理命名空间声明 ID、registry ID**，每个 EC312 manifest 各自另有从可靠独立渠道读取的全文件原字节 SHA，并且 EC314 外层 manifest 整原字节 SHA 再单独从包外信任记录提供。操作者不能从被验 JSON 本身读出自称的 SHA 即当作外部信任源。`--out` 仅由独立 CLI 可选开启新审计保存；签发密钥、CAS/Host/Provider token 不属于输入，不允许写入真实 CAS。

## EC314 私有外层 manifest 结构

```
{
  "schema": "ces.ec314.multi_window_signed_cas_mesh_manifest.v1",
  "cas_authority_id": "verified_cas_authority",
  "cas_authority_public_hex": "<real 64 lowercase Ed25519 public hex>",
  "cas_store_namespace_id": "independently_trusted_cas_namespace",
  "expected_registry_id": "independently_trusted_registry",
  "windows": [
    {"window_id": "alpha", "manifest_file": "/owner/private/alpha-ec312.json", "expected_manifest_sha256": "<external true complete raw sha>"},
    {"window_id": "bravo", "manifest_file": "/owner/private/bravo-ec312.json", "expected_manifest_sha256": "<different external true complete raw sha>"},
    {"window_id": "charlie", "manifest_file": "/owner/private/charlie-ec312.json", "expected_manifest_sha256": "<third external true complete raw sha>"}
  ]
}
```

以上尖括号部分须替换成**真实值**，不是演示 SHA/密钥。窗口 ID 严格不同且升序；3–6 个 EC312 原 manifest **两两不同整原字节 SHA**，必须完整符合原 EC312 的私有协议和输入记录。所有 manifest 是规范 JSON + 单个 LF，目录 owner-private 0700、regular 单硬链文件 0600，读取 O_NOFOLLOW/全文件 SHA/文件身份双检；新外层 32 KiB、审计最多 450 KiB。禁止额外字段、重复 key、非法 ID、伪造旧签名、缺失必要原件和自称为真实远端存储的断言。

## 运行指令

```bash
# 只读检查，不产生审计文件
python3 scripts/ces_cas_mesh.py verify \
  --manifest-file /owner/private/ec314-mesh.json \
  --expected-manifest-sha256 EXTERNALLY_PINNED_COMPLETE_RAW_SHA

# 可选：仅独立 CLI 允许 owner-private 原子不覆盖、0600/fsync 保存审计
python3 scripts/ces_cas_mesh.py verify \
  --manifest-file /owner/private/ec314-mesh.json \
  --expected-manifest-sha256 EXTERNALLY_PINNED_COMPLETE_RAW_SHA \
  --out /owner/private/fresh-ec314-audit.json

# 别的操作者从包外信任媒介获取审计完整原始 SHA，再全体原签重放
python3 scripts/ces_cas_mesh.py verify-report \
  --manifest-file /owner/private/ec314-mesh.json \
  --expected-manifest-sha256 EXTERNALLY_PINNED_COMPLETE_RAW_SHA \
  --audit-report-file /owner/private/fresh-ec314-audit.json \
  --expected-audit-report-sha256 EXTERNALLY_OBSERVED_AUDIT_RAW_SHA

# 统一控制台：固定子进程、唯一 Action/Mode、只允许 verify
python3 scripts/ces_next.py audit-mesh \
  DeliveryAudit ReconcileSignedCasWindowMesh \
  --manifest-file /owner/private/ec314-mesh.json \
  --expected-manifest-sha256 EXTERNALLY_PINNED_COMPLETE_RAW_SHA
```

`verify` 严禁传私钥/人工签字、CAS 操作或 Host/Provider 授权，`audit-mesh` 不接受 `--out`/`verify-report`；后者属于明确独立 CLI，且仍只读原真签证据，绝不提交事务。

## 关键功能规则

- **多窗口真正署名交集**：对每个节点先完全运行未修改的旧 `EC312.evaluate` 原签验证、提取签名原回执 SHA 与原 EC307 fork case/evidence、原 CAS claim/nonce、parent revision/head、结果 revision/head。任一**相同原回执 SHA** 在任意两个窗口中必须代表逐字段完全相同的真实原签来源；不能从旧输出布尔值拼接假原件。按原 issuer receipt SHA 生成全部两两交集边及 SHA anchor 列表。
- **全节点图连通、不是只挑一条看起来合理的路径**：使用稳定排序的连通分量、确定性的每节点真实原件证据路径，以及非树边构成的**额外环路交叉佐证**。有两个以上连通簇，即使所有已签 CAS revision 巧好邻接，仍 `exit2` 不选赢家。图上任意多余边不能掩盖路径内或另一环路的真签矛盾。
- **全图签名一致性，而非逐边局部通过**：按所有窗口已验 issuer **和** observer 原始签章的 `(revision, head)` 汇总，真签同修订版异 head、同 observer ID 同 sequence 不同已签原字节、跨窗口同 observer 已签 revision 倒退、另一窗口真实签名的前驱 `(sequence-1, source-SHA, revision)` 与当前签名内写明的前驱不一致，都 `exit2`。**相同完全原件在多个窗口出现是允许的**，不能误报重放。观察者同 ID 改公钥或同公钥换 ID 直接拒绝，不能自动推断密钥轮换授权。
- **Issuer 唯一、nonce 唯一、签名 parent 连续**：相同 revision 不同已签 issuer receipt 原 SHA，即使 head 相同也拒绝选赢家；不同 issuer/observer 原签来源碰巧重用同 nonce 也 `exit2`。合并所有不同真实 issuer 原签 revision 后每步必须恰好 `+1`，且下一笔的原签 CAS parent revision/head 等于上一笔真正已签结果。判别真实签名冲突优先于图不连通；无矛盾但图不连通仍不能当作已证明的连续历史。
- **仅在其他窗口含真实原签前驱时验证 opaque boundary**：非创世 predecessor 的 seq、原字节 SHA、revision、head 只要别的窗口有该 observer 真签同 sequence 必须严格相符；否则记录 `unverified`，不得捏造被审计范围之外的历史。其它窗口没有该 sequence 时不把 opaque boundary 当成已证实。观察者签名本身若带 `sequence-1`，且有真前驱原件，仍需校验其**签名声明的真实前驱 SHA/revision**。创世 boundary 不是全网初始事实证明。

分类优先级：`multi_window_authentic_signed_state_sequence_or_predecessor_conflict` → `multi_window_distinct_signed_issuer_or_nonce_source_ambiguity` → `one_or_more_original_signed_ec312_windows_not_compatible` → `multi_window_opaque_boundary_contradicts_actual_signed_predecessor` → `multi_window_signed_receipt_intersection_graph_disconnected` → `multi_window_issuer_original_parent_chain_discontinuous`。这些情况 **`exit=2`、候选=null、不得自动选赢家**。签名/原件/外部 pin/私有 ACL/身份/字段格式问题是严格拒绝 `3/4/5`，不能伪装成可认证冲突。仅全部 EC312 源码真签重验、身份/nonce/序号/签名链/全图状态/真实 issuer parent 连续、整图交集连通才 `exit=0`，此时输出的 head 仅表示**被提交的有限已签声明相容候选**。

完整审计包含每个原窗口重验摘要与原 manifest SHA、全图边/真实原件 SHA/分量/路径/环路、交叉签名异常、前驱证据、unverified 边界和最后的有界 signed candidate。审计不得携带本机私有绝对路径、私钥或凭据，严格 `0600 / O_EXCL / fsync`，二次 `verify-report` 必须有报告包外独立整原始 SHA，重新运行每条原始 EC309→294 签章后逐字段比对。

## 尚需用户最终统一验收

本轮所有 Ed25519 与本机 Host/HMAC 等真实签名事实都只能代表**本机生成与重验的原签声明**。未证明签名人的现实独立性、公钥治理/吊销、可信随机 nonce/UTC、同一个实际持久化 CAS/WORM 的真实原子并发一致性、所有窗口之外的分叉与最新记录、生产 Provider/Inbox 或独立物理存证；未完成跨机设备、Windows/macOS、PowerShell7 原15 Smoke、Git/CI/E63–E66 和最终用户联合验收。EC249/250/B001、全局 Quality PASS=false 与最终 `NOT_STARTED` 继续保持，不得把“证据图连通”声称为真实业务完成。
