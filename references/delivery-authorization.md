# EC224 — 精确交付授权绑定（独立本地关卡）

施工包 **V5.34/R224/EC224** 的 `construction/delivery_authorization.py`
提供可真实调用的 `DeliveryAuthorizer.authorize(request)`，不是 PowerShell
主 CLI `DeliverySend`，不是邮件服务、审批工作流或组织的在线身份系统。
参见严格结果 Schema `delivery-authorization-result.v1.schema.json`。

## 权限模型与接入顺序

**宿主的可信配置**必须通过独立、安全、人工/企业受控的路径事先固定
`TrustedAuthorizationRoots(issuer_id, organization_id, approver_id,
approval_public_key, organization_entitlement_public_key,
organization_revocation_public_key, minimum_revocation_epoch)`。三把不同的
Ed25519 公钥分属**具体审批人签名**、**组织权限颁发**、**组织撤销状态**；
必须与 EC223 的目录、撤销、独立身份检查三把密钥**全部互异**。
每一个 root 的归属验证、密钥发放/轮换、组织雇员关系、通道访问权限
都必须在 CES 之外由可信宿主完成。不能采用请求里附带的 key、署名者的
邮箱/Git 提交作者、SHA 等作为信任根。`approver_id` 不能等于 EC223
独立身份验证许可的 `operator_id`。这只是**不同宿主声明主体**和不同
密钥，不是对真实世界不同自然人的客观证明。

1. EC221 必须从原 EC200 Report / EC179 Finding 私有存储生成精确预览，
   EC222 必须在独立正文许可下做**实际内容检查**。只允许 EC222
   `SAFE_REDACTED_SUMMARY` 的固定文本。宿主在内存中取得这段文本的
   **原始 UTF-8 字节**，不得替换、裁剪、重新换行、添前缀或预签其他文字。
2. EC223 先在新鲜目录/撤销/独立身份验证许可下，对明确唯一的
   `project/recipient/channel/audience` 与原 EC221 目的地承诺进行一致
   核验。保存其 `cesdi1:` 证明 ID、`source_set_sha256`、来源哈希、
   固定政策、目标/路由/撤销/身份信任锚摘要。EC223 身份检查许可本身
   **绝非交付许可**。
3. 宿主向**另一把组织权限签名密钥**取得受限 `entitlement` 声明：
   固定项目、同一身份证明 ID、路由、目标、实际 payload SHA、
   EC223 `source_set_sha256`、审批人和其签名公钥 SHA、组织/审批人
   `ACTIVE` 状态、`INTERNAL_DELIVERY_APPROVER`、隐私等级上限、
   `may_approve_exact_internal_review=true`、组织授权 epoch、短期时效；
   声明中另绑定含六把根 key 的 `authorization_trust_anchor_binding_sha256`。
4. **先由独立组织撤销密钥签署 snapshot，再由审批人签 grant。**
   snapshot 包含组织、审批人、签名 key、entitlement、指定授权 nonce
   的五种 `ACTIVE` 状态，精确 identity/route/destination/entitlement、
   来源版本集、payload SHA、隐私下限、政策/代码哈希、根 key 绑定和
   授权 epoch；`issued_at` 不得早于 entitlement。`minimum_revocation_epoch`
   必须由**宿主可信状态**设置与推进。撤销 snapshot 的有效时窗 ≤45 秒。
   这不能替代在线撤销查询：签名后立即变化的外部状态只有在宿主推进
   最小 epoch 或失效密钥后才能被挡住，故本地收据不能被直接用于网络发送。
5. **审批人**用独立的预固定审批私钥签 exact grant：必须绑定
   `approval_nonce`（32 个小写十六进制字符）、精确项目与三个稳定
   目标 ID/域 SHA、EC223 身份 ID、身份与授权信任根 SHA、
   EC223 目录路由/身份撤销检查点、EC221 preview、EC222 review、
   `dr.ACTIVE_POLICY_SHA256`、`ACTIVE_APPROVAL_CODE_SHA256`、
   `source_set_sha256`、payload SHA/长度/MIME/隐私下限、entitlement SHA
   和**本轮组织撤销 snapshot SHA**，以及 issuance/expiration。
   grant 必须在 snapshot 签发后、snapshot 未过期前签署；总时窗
   ≤90 秒，且在 entitlement 的 ≤180 秒时窗之内。
6. 本地 `authorize()` 首先对**所有独立签名/时效/精确范围**做 fail-closed
   预检，未经预检不读私有源码或 Report。通过后调用真正的
   `DeliveryIdentityVerifier.verify()`，再完整运行 EC222 → EC221
   对原私有 Report/Finding 存储的实际内容/版本重读，不能凭任意
   `safe=true`、伪造的 EC223 JSON、用户声称的身份或已签文件名代替。
   重读后逐个重比对 identity ID、SHA、payload 原始字节 SHA、
   source version set、隐私等级与项目、目的地、身份撤销，并再检查
   grant、组织权限、组织撤销、EC223 目录/撤销/身份检查许可的时效。
   本地实现代码与上游 EC221/222/223 的文件指纹同时纳入新审批
   代码哈希；处理中源码漂移也会阻断。

## 签名格式与调用

三个 `SignedAuthorizationStatement(statement, signature_hex)` 都是严格
JSON 对象，无额外字段；编码统一使用
`delivery_preview.canonical(statement)`（ASCII、排序键、定界确定、
拒绝 NaN），签名消息为 **domain bytes + canonical JSON bytes**。
三个不互通的签名域依次为代码中的 `ENTITLEMENT_DOMAIN`、
`REVOCATION_DOMAIN`、`GRANT_DOMAIN`。签名用原生 Ed25519 的 64 字节
签名十六进制小写表示；签名明文可能含目标稳定 ID，**只在经过授权的
本地安全通道传输，不日志落盘、也不返回给 UI**。

调用者创建 `DeliveryAuthorizationRequest(identity_request=<原EC223精确请求>,
expected_identity_verification_id=<原cesdi1 ID>, exact_payload_bytes=<原EC222
UTF8 bytes>, organization_entitlement=<签名声明>,
organization_revocation_checkpoint=<签名声明>, exact_delivery_grant=<签名声明>,
permit_independent_delivery_authorization=True)`，再调用
`DeliveryAuthorizer(authorization_roots, identity_verifier).authorize(request)`。
不得用代码示例/fixture 的临时密钥作为生产信任根。

## 返回、拒绝与边界

`partial/2` **仅**说明在当前宿主已固定信任根和私有重读条件下，取得
**精确本地审批凭据** `cesda1:`。该结果默认包含不可反推出明文的
域分离来源/目标/版本/权限/内容 SHA、有效截止 Unix 秒、三重签名
校验状态；`effects.delivery_authorized=true` **仅意指本地的 exact
scope 批准**，绝非在线投递、真人身份核实、组织脱密、当前 Provider
接入权或一次性执行许可证。

- `blocked/5`：任一签名不符、精确绑定不符、已撤销或权限不足；
  `invalid_input/4`：对象格式/字段/类型不符合固定契约；
  `unavailable/5`：独立许可缺失、私有真实重读不可用、过程中到期、
  时钟倒退或代码指纹失效。
- 所有拒绝都只输出固定原因码，不回显密钥、原文、路径、项目 ID、
  接收者 ID 或异常内容。成功也不输出 Markdown、联系人或凭据。
- `message_sent`, `delivered`, `published`, `ready_to_send` 始终为
  **false**；没有网络连接、邮件/API token、Issue/Git 写入或 CES
  记录保存。只处理目前 EC223 支持的**项目私有、内部单接收者**，
  绝不授权外部/broadcast 分发或更高保密内容的自动脱密。
- **无持久化 one-use ledger，无法阻止有效期内重复消费；** no live
  organization/provider ACL, no atomic cross-store snapshot, no live
  revocation guarantee after checkpoint issue. 下一轮 EC225 如果施工
  真实 Provider 发送，必须先按其独立发送政策重新验证全部这些状态，
  实现独立副作用授权、one-use/幂等持久化及前后远端状态确认，不能
  因本轮 receipt 存在就直接投递。

## 开发 fixture 与待验收

`construction/test_delivery_authorization.py` 覆盖实际临时 EC200
私有报告 → EC221 预览 → EC222 真实内容扫描 → EC223 签名身份
→ EC224 两角色三签名绑定；包含内容字节变动、审批人/企业权限
身份分离、渠道/收件人/项目变化、独立签名伪造、撤销轮换、源码策略
SHA、源版本 SHA、时钟到期、私库不可用、缺失许可和零发送副作用。
合成 Ed25519 密钥 **不是**现实中的企业/人证据。真实权限根、审批流程、
撤销传播和时钟安全、组织 PII 策略、Provider、OS/NFS/并发，
Windows/macOS/Linux、PowerShell7/15 Smoke、E63–E66、全链路及
最终用户辅助验收统一标记 **NOT_RUN**，B-001 仍 OPEN。
