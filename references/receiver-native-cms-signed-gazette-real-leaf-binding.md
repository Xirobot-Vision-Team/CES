# EC400 接收者协议：真正 RFC5652 DER CMS/PKCS#7 SignedData 双签与旧公报原字节绑定

**版本：** V7.10 / R400 / EC400。**性质：** 只读、本地、受限原始材料接收器；验签/证据检查，不是官方法律资格认证、CA 系统、时间戳服务、签发工具或法定验收。下一层外部证据缺失时必须保持 `exit 2 / *_unresolved`。

## 本轮新增的真实实现边界

- 每次运行，**必须调用原来的 `official_certificate.protocol.audit()`**。该原始入口继续实际调用 EC398、397、396、395、394、393、392 和两份 EC391 审计；不能由新增客户端 JSON 提交祖先 PASS。EC400 额外校验真实 EC399 返回报表的全部固定字段、状态、逐 epoch 计数、全局库存 SHA、原父捆绑文件 SHA 和无权利断言。
- 回读真正 EC399 bundle、外存钉住的两份证书签发者 roster、各自的叶→可选中间 CA→根的全部证书原件。**重新调用真实 EC399 的 `_chain()`** 进行 CA 路径、证书签名、政策 OID、EKU、SPKI SHA、根证书 SHA 校验；不从 CMS 内嵌证书自行授信。
- 真实重新打开 EC398 的 Ed25519 签署公告、验其签名和原始 source 的 SHA/原字节，另打开 EC397、396、395 bundle/role 原始材料保护路径不可别名。
- 接受长度上限 **1,500,000 bytes** 的**原始 DER ContentInfo / SignedData**。支持 `id-data` 的 **detached CMS**（无 eContent）和 **attached CMS**（eContent 必须逐字节等于 EC398 真正公报原字节）。仅支持实际验证的标准 CMS 结构，不把 EC399 的自定义签名 JSON 当 CMS，也不识别 PDF PAdES/XMLDSig/TST/CAdES 法律资格。
- 强制 **恰好两个** CMS `SignerInfo`，分别必须能以 issuer+serial（或证书中已存在的 SKI）找到 EC399 两个不同的、原证书 SHA 精确匹配的叶证书。CMS 中必须嵌入全部两份叶 DER；可选加入 EC399 已知且字节 SHA 匹配的 CA 证书，不允许未知/额外证书。两证书必须有真实 parent 历史/evaluation CRL 覆盖，才能参与**联合可信数**。
- 严格检查 CMS `signedAttrs` **DER SET OF 排序及 IMPLICIT `[0]` 原编码**。在密码学上验证签名的输入为 **0x31 DER SET OF** 而不是原公报字节本身或 `0xA0` 的 IMPLICIT 编码。强制 signed contentType=`id-data`、唯一 messageDigest=**真正 reopened source 字节**哈希、唯一 signingTime 与先前 EC398 真实签署 claim UTC 完全相等（精确到秒，且在完整证书有效期内）。拒绝重复属性、SHA1/弱算法、伪签名、伪造消息哈希、签名人身份替换、缺失双方及受污染原件。
- 算法白名单：CMS digest SHA-256/SHA-384/SHA-512；SignerInfo signature Ed25519+SHA-512、P-256/P-384 ECDSA+对应 SHA2、RSA PKCS#1 v1.5/SHA2（根/叶本身还必须符合 EC399 独立 X.509/CRL 检查）。不支持 SHA1、DSA、RSA-PSS、未知算法、混入任意 CRL/OCSP 或非 DER BER（没有误称它们已验证）。签名 `unsignedAttrs` 不提供信任加分。
- 所有新原件用绝对归一化路径加 SHA 的**原始字节**输入；两期 CMS 路径不可重复，不得复用父证书、源公报、签署公告、父 CRL、任何指定祖先 source 等路径。最后逐一按 SHA 和边界字节重读，保持无写入。
- 外存预先留存三个层级：原 EC400 bundle SHA、第一 epoch CMS 原件 SHA、每个 epoch 的本地验证 inventory SHA/本地核验数量最小值、整个 unsigned inventory SHA。`derive` 无签返回库存，不会替用户构造“外部事前存证”；`audit` 比对**独立留存**的 SHA，矛盾仅给不利旗标，不能把本地计算后自己填写当成独立可信来源。

## 原件 JSON（所有键精确匹配，禁止额外字段）

**Bundle 源文件**：UTF-8，严格 JSON，不接受重复成员，最多 90,000 bytes。

```json
{
  "schema": "ces.ec400.native_cms_gazette_original_bundle.v1",
  "claimed_directory_lineage_id": "<同 EC399/EC398 已核对的 lineage>",
  "parent_ec399_official_certificate_bundle_original": {
    "path": "/ABS/PATH/actual_ec399_bundle.json",
    "sha256": "<其完整原始字节的 64 位小写 SHA-256>"
  },
  "epochs": [
    {
      "epoch_index": 0,
      "cms_signed_data_original": {
        "path": "/ABS/PATH/genuine_cms_original.der",
        "sha256": "<原始 DER CMS 的小写 SHA-256>"
      }
    }
  ]
}
```

- `epochs` 与父 EC399 真实 1～3 epoch 数量相等，索引从 0 连续。缺 CMS 时该 epoch 的 `cms_signed_data_original` 可以为 JSON `null`，结果为不利未完成和零联合信用，不是伪 PASS。
- 不接受 CMS 生成器后来重写为另一份 DER 原件；绝对路径的**原始字节**和独立 SHA pin 才是比较对象。若原始 CMS 自行附带内容，必须逐字节匹配真实父源。
- 对来源/时间和用户角色的信任只传递自**真实重新核验**的 EC399、EC398，不读取发送者源文件，也不从客户端报告构造已验证证书/CRL。

## 命令

```bash
cd ces
python -I -B scripts/ces_cas_historical_native_cms.py derive-historical-ec339-native-cms-inventory --help
python -I -B scripts/ces_cas_historical_native_cms.py audit-historical-ec339-native-cms --help
python -I -B scripts/ces_next.py audit-historical-ec339-native-cms DeliveryAudit AuditHistoricalEC339NativeCMS --help
```

完整执行必须提供**所有** EC399 audit 参数（和更深的真实祖先输入）及以下新增参数：

| 参数 | 用途 |
|---|---|
| `--historical-ec339-native-cms-bundle-file` | EC400 原始 bundle 绝对路径 |
| `--expected-historical-ec339-native-cms-bundle-sha256` | 外渠道持有 bundle 原字节 SHA |
| `--expected-outside-retained-ec400-first-native-cms-original-sha256` | 第一 epoch 外渠道保留 CMS 原始 SHA |
| `--historical-ec339-native-cms-epoch-inventory-sha256` | 按 epoch 传入预先持有的 SHA（重复 1～3 次） |
| `--minimum-historical-ec339-native-cms-verified-signer-count` | 按 epoch 传入本地联合核验下界 0..2（重复 1～3 次） |
| `--expected-retained-historical-ec339-native-cms-inventory-sha256` | **仅 audit** 必填，外渠道保留整个 unsigned inventory SHA |

所有继承的参数均为必需，不能跳过 EC399 审计、CRL、证书名册或 EC398 真公报签名。`derive` 输出 `unsigned_native_cms_inventory` 供外部核对，而不将它写回业务源；不能把运行时自己计算的 digest 谎称早于争议已保存在独立保管方。

## 返回值与出错语义

- 合法可审但不可完成现实意义验收的结果：`exit_code=2`，`status=ec400_*_unresolved`，返回两重父报告/库存 digest、真实原 CMS 源 digest、每 epoch 原件/签名方/源哈希/签名类型的观察，绝不直接 `PASS`。
- EC399 母审计签名撤销或 CRL 缺失，CMS 签名即使真实也**不计入联合可信人数**；第一份外存 pin、不一致库存/数量、缺失 CMS 返回不利旗标，不会因为签名算法强就替代历史证据。
- 伪造/破损/算法降级/属性注入/源字节不一致/证书不匹配：`permission_denied` / exit 3；非法输入 exit 4；缺文件/依赖/父错误 exit 5。`operator` 仅在 stderr 无私人机密的前提下输出严格 JSON denial。不会关闭先前不利旗标。

## 不会因本轮完成而成立的内容

1. EC399 的两个本地被钉住证书根与 CMS 双签 **并不证明** 政府、法院或真正官方公报主体具备法定授权；原始公报内容自己也可能不是官宣材料。缺少**独立、事前、可公开交叉验证的**官方信任锚、实际授权文件、政策和法律验收。
2. 普通 CMS `signingTime` 是签署人可自主填的签名属性，**不等于 RFC3161 合格 TSA、发文生效时间或事件发生的外部证明**。认证的历史时间链和 dispute cutoff 仍需要真实第三方材料。
3. 离线给定 CRL 不覆盖真实世界全体 OCSP、全球撤销时间、隐藏分叉；签发方可在现实中被撤销。旧历史 CRL 校验由 EC399 强制调用，不可通过这份 CMS 绕过。
4. 标准 CMS `id-data` SignedData 不是 PAdES PDF、XMLDSig/XAdES、国家专用签章规范。若现实官方公报依赖某专有格式，需要下一轮**独立**解析器和实际法律授权证据。
5. 没有真实独立来源预先公示查询/历史镜像、厂家认证物理 WORM/HSM、不模拟的全部长期外部祖先链、原生 PS7/15 Smoke/Windows/macOS、CI/Provider/性能和最终联合验收结果。

本轮本地测试使用合成自签 X.509/CRL、真正 Ed25519/P-256 CMS DER；**EC399 的 outer audit 和更深祖先由测试模拟**，不是无 mock 的现实历史链。附加使用 OpenSSL `cms -verify -binary -noverify` 交叉验真 1 份真实合成双签原件，仅证明标准 CMS 签名结构与内容哈希的互操作性，**不核验 OpenSSL 信任根（`-noverify`）或现实法定资格**。真实 official original、对外根/授权/CRL、真实完整祖先链未提供，故 remain NOT_PROVEN。
