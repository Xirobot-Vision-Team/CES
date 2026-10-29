# EC401 — 真正 DER/RFC6960 OCSP 原件双时点验证：精确协议与证据边界

本层不是官方政府/司法认可凭证、不是联网 OCSP 查询器，也不认定任何证书为合法政府机关。只读本机原件，并且**生产调用必须完整执行原封不动的 EC400 `audit()`**（EC399 的双证书链与签名 CRL、EC398 真公报原件、CMS 双签名及其全部祖先）。本层无法弥补父链任何失败。

## 完整调用方式

```bash
cd ces
python -I -B scripts/ces_cas_historical_issuer_ocsp.py derive-historical-ec339-issuer-ocsp-inventory --help
python -I -B scripts/ces_cas_historical_issuer_ocsp.py audit-historical-ec339-issuer-ocsp --help
python -I -B scripts/ces_next.py audit-historical-ec339-issuer-ocsp DeliveryAudit AuditHistoricalEC339IssuerOCSP --help
```

安装要求：当前针对性运行于 Python 3.13、`cryptography 46.0.4`、`asn1crypto 1.5.1`；使用多响应 OCSP API 与 `_utc` 时间值，移植到旧 cryptography 版本前**必须兼容性测试**。接收器本身不生成 CA、私钥、签名或原件，且不进行网络访问。fixture 仅供本地测试，使用临时合成密钥签署 OCSP 响应，不是合法外部发行记录。

继承命令行参数：**EC400 完整 `audit-historical-ec339-native-cms` 参数集**，包含所有父层独立外存 SHA、源原件路径、逐 epoch SHA/count 下界和父 whole unsigned inventory SHA；不能省略。新增：

| 参数名 | 含义 |
|---|---|
| `--historical-ec339-issuer-ocsp-bundle-file` | 严格规范化的绝对路径，OCSP 清单 JSON 原件 |
| `--expected-historical-ec339-issuer-ocsp-bundle-sha256` | 外部预先持有的上述 JSON 原件完整 SHA-256 |
| `--expected-outside-retained-ec401-first-a-historical-ocsp-sha256` | EC399 roster 第一个真实 publisher 第一个 epoch 叶证书历史 OCSP 原件 SHA |
| `--expected-outside-retained-ec401-first-b-historical-ocsp-sha256` | EC399 roster 第二个真实 publisher 第一个 epoch 叶证书历史 OCSP 原件 SHA；必须与 A 不同 |
| `--historical-ec339-issuer-ocsp-epoch-inventory-sha256` | 每期一次、顺序提供的签名 OCSP 原件归一化清单 SHA，次数等于父历史期数（1～3） |
| `--minimum-historical-ec339-joint-ocsp-publisher-count` | 每期一次，0～2 的父 CMS+CRL+本层真实 signed GOOD OCSP 联合计数下界 |
| `--expected-retained-historical-ec339-issuer-ocsp-inventory-sha256` | **仅 audit**，独立渠道保管的整份 unsigned OCSP inventory SHA（derive 的返回值不构成外部信任） |

每个 `--historical-ec339-issuer-ocsp-epoch-inventory-sha256`/`--minimum-...` 可重复，必须与历史 epoch 数一一对应。`derive` 在合法但尚未外存钉住全部摘要的场景下输出 `unsigned_ocsp_evidence_inventory` 供**另渠道保存和复核**，并始终 `exit 2 / *_unresolved`；`audit` 对照独立输入摘要，成功解析不等于法律合格。非 2 的返回值：3 permission_denied（篡改/角色冲突/弱协议）、4 invalid_input（结构/参数）、5 unavailable（缺依赖/读取失败/父审计失败）。

## 原件 bundle — 严格 JSON schema（所有键必须恰好一致）

```json
{
  "schema": "ces.ec401.issuer_signed_ocsp_originals_bundle.v1",
  "claimed_directory_lineage_id": "same-as-real-parent-lineage",
  "parent_ec400_native_cms_bundle_original": {"path": "/absolute/parent/ec400.json", "sha256": "<sha256>"},
  "epochs": [{
    "epoch_index": 0,
    "publishers": [{
      "publisher_id": "publisher-id-from-real-ec399-roster",
      "chain_links": [{
        "subject_certificate_sha256": "<EC399-leaf-original-DER-sha256>",
        "issuer_certificate_sha256": "<EC399-immediate-issuer-DER-sha256>",
        "historical_ocsp_response_original": {"path": "/absolute/epoch0/publisherA/historical.ocsp.der", "sha256": "<sha256>"},
        "evaluation_ocsp_response_original": {"path": "/absolute/epoch0/publisherA/evaluation.ocsp.der", "sha256": "<sha256>"},
        "historical_responder_certificate_original": null,
        "evaluation_responder_certificate_original": null
      }]
    }]
  }]
}
```

样例仅显示**一个 publisher / 一个 link** 的形状。每期必须**恰好两个**不同的真实 EC399 roster publisher；每个 `chain_links` 必须覆盖该发行人的每个链路：叶→（中间 CA→）信任根，严格固定方向与 exact 原件 SHA。真实生产要提供两个 publisher 的全套 `chain_links`，每个 link 的四个 role-specific 原件字段均必须出现。

若响应缺失，则相应 `*_ocsp_response_original` 可以是 `null`，但不得同时提供对应代理证书；缺失不产生 GOOD 计数，会设置 incomplete/unavailable 标识。OCSP 原件和代理证书原件不能复用同一绝对路径，不能与任何可追溯的父层 rosters、CMS、签名公报、CRL、证书、证据清单路径混用，也不能跨期互相充当相同原件。全部原件读取限制尺寸、按给定 SHA 验证、末尾再次逐原始字节读回。

## 真正验证的密码学和时间语义

1. **单目标原件：** 用 `cryptography.x509.ocsp` 解析完整 DER OCSPResponse；必须是 `SUCCESSFUL` 的恰好一项 BasicOCSPResponse / SingleResponse，不接纳混合/多对象、非 canonical DER、未知响应扩展；只允许证书 `CertID` 的 SHA-256/384/512，拒绝 SHA-1。使用真实 EC399 证书对 **serial / issuerNameHash / issuerKeyHash** 三元组重新构造并逐字节匹配。
2. **真实签名者：** 无代理证书时只能由真实 EC399 该链路证书发行者公钥直接签署，不可附带额外不明证书。代理模式需原始证书 DER 完整 SHA 和 OCSP 中**恰好相同的一份**嵌入证书，真 issuer 签发证书链签名、issuer subject、有效期、非 CA、digitalSignature KU、`id-kp-OCSPSigning` EKU 和明确 OCSPNoCheck issuer 授权；未知 critical 扩展拒绝。证书 `responderID` byName/byKey 必须与实际验签的该证书吻合；Ed25519、P256/P384 ECDSA、强 SHA2 RSA 使用原 EC399 受控验签器，无弱算法退化。NoCheck 是发行者授权跳过代理撤销检查的**局部协议特性**，并非全球无撤销的独立证明。
3. **两份不同时间原件：** 对每个链路重新计算父 EC398 真签名 notice `claimed_published_utc` 与继承的 `ec391_tsa_evaluation_utc`；对历史和核验时点各一份独立原件验证 `thisUpdate <= target <= nextUpdate`，`producedAt` 位于响应自身有效窗（容许 5 分钟偏差），且不得晚于 caller 提供的核验时点；历史原件 `producedAt` 不得晚于历史 notice UTC 超过 5 分钟，核验原件 `producedAt` 不能偏离核验 UTC 超过 5 分钟。**事后重新签发即便指向旧窗口，也不能给历史在场计数。** 这种带容差的签署者声明仍不是独立法定时间戳。
4. **真实撤销/UNKNOWN：** 真签名 `GOOD`、`REVOKED`、`UNKNOWN` 均记录。任何 revoked/unknown/过期/缺失/非同时期原件不计局部 GOOD 联合下界；真实篡改、假签、身份错位、无授权代理、非法 DER 等拒绝而不是软性标记为 SUCCESS。不得利用新 OCSP “修复” EC399 的任何 CRL 冲突。
5. **摘要和状态：** EC400 真实重跑报告的 exact schema/flags/status、CMS 两签名 epoch 数和父 unsigned inventory SHA 必须对齐；EC401 的每期签名 OCSP 清单 SHA、两个首期原件外存 SHA、整份无签名 inventory SHA 均比较。所有合法结果 `_unresolved / exit2`，所有表达“官方合规已验证、独立 TSA、全球吊销证据、实体 WORM、最终验收”的 negative-capability 位永久为 `false`。

**刻意不支持：** 联网获取 OCSP/CRL，未经外部认定的法律/司法公钥根、实时开放目录、PDF PAdES/XMLDSig、回应 nonce 的在线请求绑定、OCSP 同包多 SingleResponse、未经 NoCheck 授权的代理签署、unknown critical 响应扩展、RFC 3161 qualified time 对此层响应的独立证实、OCSP 服务端可用性/完全记录集。真实历史线上材料、取消/继承公文、真实外部信任资格、全量祖先无 mock 和 Windows/macOS/PowerShell 仍待用户统一验收。
