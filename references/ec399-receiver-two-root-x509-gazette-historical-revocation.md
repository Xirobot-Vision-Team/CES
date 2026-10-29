# EC399：双根 X.509 原件签署、公报源码 SHA 绑定、历史与核验时点 CRL 交叉检查

**版本 V7.09 / R399 / EC399，2026-10-26。** 这是严格离线、只读的**可复核本地密码学协议**，不是现实政府/法院的资质证明、合法性裁决、官方公报原生 CMS/PAdES/XML 签名格式支持，也不是在线 OCSP/完整撤销、可信法律钟、事前公示或物理 WORM 的证明。**恰当提供的证据一律 `exit 2` 与 `_unresolved`，无条件不发布合规 PASS。**

## 施工所解决的功能缺口

EC398 只有新 registrar 的 Ed25519 签署与 opaque 公报源 SHA：即使父链全部通过，该原件也不带可信 X.509 官方发行根。EC399 每次生产 derive/audit 都直接调用**未修改** `ec398_official_notice.protocol.audit(**inherited)`，后者继续调用 EC397、EC396、EC395、EC394、EC393、EC392、两个 EC391 及祖先，不收调用者提供的父 PASS。EC399 精确检查父报告的所有预期字段、真假布尔位、状态选择、每期数量和 digest 汇总、真实父 `bundle` 与真实父最终 inventory SHA。再从**父 bundle 实际引用**重新打开 EC398 签名公告原件和 opaque source，验证 EC398 Ed25519 原签；独立 X.509 声明精确绑定该原件字节 SHA、原 EC396 已签注册快照 SHA、父 bundle/inventory SHA、epoch/角色/上轮声明签名原字节 SHA/签署时间。

对每个 epoch 两位新颁发人分别有**自带的事先外部保留的 DER 根证书 SHA256**、**叶证书 DER SubjectPublicKeyInfo SHA256** 和相同的**外部预存许可策略 OID**。二者在原始 SHA 固定的新证书名册里约定独立 publisher/site、leaf→可选 intermediate→self-signed root 的**完整有序 DER 路径**（2 或 3 张证书）；不允许新两位发行人的 cert path/key/身份互相复用，且比对旧 EC398 Ed25519 密钥不复用。对所有 cert 验证强算法真正签名（Ed25519、P-256/P-384 ECDSA、强 RSA PKCS#1 v1.5 SHA-2），禁止 RSA-PSS/DSA/SHA1 与不支持曲线的静默回退。检验证书 BasicConstraints、KeyUsage、pathLen、AuthorityKeyIdentifier/SubjectKeyIdentifier、保守拒绝未知 critical 扩展和无法执行的 Name/Policy constraints，叶子要求具体 EKU OID 与**外部钉住的 CertificatePolicies OID**，证书链逐张检验声明签署 UTC 时有效。根本身仅凭外部 SHA 信任（**谁钉住的根、它有没有合法法定授权须另证明**）。

每个 leaf 和可选 intermediate **逐链边**使用发证 issuer 真签名的**两份原始 DER CRL**：一份明确涵盖被签公告 UTC，另一份涵盖继承自 EC391 参数的核验 UTC（不宣称自动当前时间）。完整检查 CRL issuer 名称/AKI、真正签名、`thisUpdate <= UTC <= nextUpdate`、证书 serial 的 revocationDate、非 delta/非间接/非分区以及历史到核验 CRL 的时间/序列不倒退。撤销或任何一份缺失/过期只导致计数为零、保留不利旗标，**不伪造“CRL 绿灯”**；假签名、坏 DER、别名、不认可的扩展是拒绝结果（3/4/5），不是局部 PASS。

两名 publisher 各自用真实叶证书私钥在**项目之外**已经生成的签名对 `domain_bytes + inherited_ec319.canonical(claim)` 验签（接收器绝不生成私钥/证书/CRL/签名）。Ed25519/ECDSA/RSA PKCS#1 v1.5 的 leaf 使用固定安全算法；声明始终是**CES EC399 域隔离 detached hash commitment**，不冒充政府原生签名标准。任何一名失去历史 predecessor 连续性、证书截止或 CRL 时效，之后不能凭新声明恢复此前计数。两条链均与真实 EC398 四个活跃角色、双保管者凭据相符才会有最多 2/epoch 的本地计数。每期签名摘要 SHA、CRL 摘要 SHA 和计数 floor 必须和外部先前保留值一致；首期双签名原件独立 SHA、两 root DER SHA、两个 leaf SPKI SHA、整个 unsigned inventory 的异渠道预留 SHA 亦复核。

## CLI（无网络、无原件写入）

```bash
cd ces
python -I -B scripts/ces_cas_historical_ec339_official_certificate.py derive-historical-ec339-official-certificate-inventory --help
python -I -B scripts/ces_cas_historical_ec339_official_certificate.py audit-historical-ec339-official-certificate --help
python -I -B scripts/ces_next.py audit-historical-ec339-official-certificate DeliveryAudit AuditHistoricalEC339OfficialCertificate --help
```

所有 EC398 **audit** 参数，包括过去所有祖先的正式 SHA/角色、全部重复值、`--expected-retained-historical-ec339-external-notice-inventory-sha256` **必须原样提供**，否则不会绕开真实父链。其余新增参数名称统一为下列 key 中 `_` 换为 `-` 并加 `--`：

| 类型 | Key | 语义 |
|---|---|---|
| scalar | `historical_ec339_official_certificate_bundle_file` | EC399 bundle 原件的规范绝对路径 |
| scalar | `expected_historical_ec339_official_certificate_bundle_sha256` | 与上一项原件独立外存 SHA |
| scalar | `expected_outside_retained_ec399_publisher_roster_sha256` | 双新角色原始名册外存 SHA |
| scalar | `expected_outside_retained_ec399_publisher_a_trust_root_der_sha256` | A 根证书**原始 DER** 的 SHA |
| scalar | `expected_outside_retained_ec399_publisher_b_trust_root_der_sha256` | B 根证书 DER SHA，不能等于 A |
| scalar | `expected_outside_retained_ec399_publisher_a_leaf_spki_sha256` | A leaf SPKI DER SHA |
| scalar | `expected_outside_retained_ec399_publisher_b_leaf_spki_sha256` | B leaf SPKI DER SHA，不能等于 A |
| scalar | `expected_outside_retained_ec399_publisher_policy_oid` | 原始外渠道钉住的 leaf 证书许可策略 OID（例如测试自造 OID 不具法定效力） |
| scalar | `expected_outside_retained_ec399_first_publisher_a_signature_sha256` | 第一个 epoch 的 A 签名 JSON 原字节 SHA |
| scalar | `expected_outside_retained_ec399_first_publisher_b_signature_sha256` | 第一个 epoch 的 B 签名 JSON 原字节 SHA |
| audit-only | `expected_retained_historical_ec339_official_certificate_inventory_sha256` | **预先独立持有**的完整 unsigned inventory SHA，不得 derive 后自行伪造事前留存 |
| repeat, per epoch | `--historical-ec339-official-publisher-signed-original-inventory-sha256` | 本期两签名摘要的外存 SHA |
| repeat, per epoch | `--historical-ec339-official-publisher-crl-inventory-sha256` | 本期两签发链历史/核验 CRL 状态摘要外存 SHA |
| repeat, per epoch | `--minimum-historical-ec339-two-root-certificate-publisher-count` | 外存整数 floor `0..2`，缺任何状态不计数 |

每个 original 文件引用均为对象 `{ "path": "/normalized/absolute/file", "sha256": "64-char-lowercase-nonzero-hex" }`，继承读者严格防软链/别名，所有原件字节有限额并在返回前重读。签名 JSON 限 25KB、证书 DER 每个 24KB、CRL DER 每份 2MB、bundle 240KB、roster 30KB，历史 epoch 1..3。任何原始父数据、issuer CA、CRL/new signature 不得共用相同路径；每条完整路径不允跨用途复用。

## 精确原件格式

**外部名册**：`schema = "ces.ec399.two_independently_pinned_publisher_x509_roster.v1"`，字段只有 `schema`、`claimed_directory_lineage_id`、`publishers`（**长度必须 2、顺序决定 A/B pins**）。每个 `publishers[]` 只能含 `publisher_id`、`site_id`、`certificate_chain_originals`（有序 `[leaf, optional intermediate, root]` 原始 `path/sha`）、`required_policy_oid`、`required_publisher_eku_oid`。所有 cert 都是完整原始 **DER**、不是 PEM、截断缓存或任意证书查询结果。指定的 EKU OID 必须真实出现在叶证书 EKU 中；指定的策略 OID 必须与 CLI 外存预留且真实位于叶证书 policy 中；存在中间 CA policy 时同样需允许该 OID。

**EC399 bundle**：`schema = "ces.ec399.two_root_gazette_certificate_originals_bundle.v1"`，字段只有 `schema`、`claimed_directory_lineage_id`、`parent_ec398_external_notice_bundle_original`（必须等于上次 audit 提供的 EC398 原件） 、`outside_publisher_roster_original`、`epochs`。`epochs[i]` 有 `epoch_index = i` 和 `publishers`（长度 2，各 id 与名册一致），每个 publisher row 有：

```json
{
  "publisher_id":"PublisherA",
  "signed_gazette_attestation_original": {"path":"/abs/signed-a.json","sha256":"<SHA256>"},
  "issuer_crl_coverage":[
    {"issuer_certificate_sha256":"<immediate issuer DER SHA256>",
     "historical_crl_original":{"path":"/abs/crl-hist.der","sha256":"<SHA256>"},
     "evaluation_crl_original":{"path":"/abs/crl-eval.der","sha256":"<SHA256>"}}
  ]
}
```

2 证书链只要一条 CRL row；3 证书链要两条按 *leaf 的 issuer* 再 *intermediate 的 issuer* 排列。若完全没有外部签名，`signed_gazette_attestation_original=null` 且 `issuer_crl_coverage=null` 只得 unresolved/零信用；若签名存在但 CRL 不存在，`issuer_crl_coverage=null` 也只能 unresolved。某份独立 CRL 缺失则该 JSON ref 为 `null`；有材料但 DER、签名、对应 issuer 错误将拒绝。两条证据时间线均用**原签名证明、不能由接收器构造**。

**签名 JSON 原件**：`schema = "ces.ec399.detached_publisher_gazette_signature_original.v1"`、`claim`、`signature_base64`（标准严格 base64）。`claim` 精确有：`schema = "ces.ec399.detached_publisher_gazette_signature_claim.v1"`、`directory_lineage_id`、`epoch_index`、`publisher_id`、`parent_ec398_bundle_sha256`、`parent_ec398_verified_inventory_sha256`、`parent_signed_notice_original_sha256`、`parent_ec396_signed_registry_snapshot_sha256`、`source_gazette_original_sha256`、`leaf_certificate_der_sha256`、`certificate_chain_sha256`（canonical JSON 的原 cert SHA 数组摘要）、`previous_signed_attestation_original_sha256`（第一期 64 个 `0`）、`claimed_published_utc`（必须等于**真正 EC398 已签公报**的同一 UTC）、`required_policy_oid`。签名消息字节：`b"CES/EC399/OfflineX509GazettePublisherOriginal/v1\\0"`（最后一字节实为 `NUL`）接 `ec319_offline_transfer_registry.registry.canonical(claim)`。私钥只在外部材料产生方持有，CES 完全不可签署。

## 外部证据仍需用户最终联合验收

受约束的 X.509 证书链和 issuer CRL 能证明**用户指定信任根**下的文件 SHA 及证书签名/局部撤销情况，不能自己证明该根获得法院、监管/政府法定授权，不能取代官方原生 CMS/PDF/XML/DOC 原件验签，不能证明外界确曾收到/事先公开同一公报，也不能凭离线 CRL 覆盖在线 OCSP、全网密钥历史、根自身妥协或 qualified TSA 时间。EC399 不生成认证报告的 `PASS`，最终不自动提升 Quality。

**本轮观测范围：** 25/25 真实本地 X.509（Ed25519 + P-256，含中间 CA）签名/原始 DER CRL、真正的 SHA 回读和拒绝/不利情况用例执行通过；**完整 EC398 父 `audit` 是本地测试中的 mock**，更深祖先和真实官方原件/外部 DER/TSA 端到端没有测试/认定。原生 PowerShell 7/原始 15 Smoke、Windows/macOS、真实 Git/CI/Provider E63-E66、性能、独立官方文档签章、HSM/WORM、公众检索及最终用户联合验收均 **NOT_RUN/NOT_PROVEN**。
