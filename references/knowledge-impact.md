# EC204 — KnowledgeImpact 可信目标的受限 Git 变更集合

**版本 V5.14 / R204 / EC-204。** 本文件描述已实现的独立 Python 组件 `construction/knowledge_impact.py`，并不是 PowerShell R150 原生命令、知识章节定位、知识修改或自动发布。

## 1. 做了什么

`KnowledgeImpact.analyze()` **每次调用重新运行完整 EC203**，实际核对 EC202 选定的本地文件字节、目标 Git commit SHA-1/SHA-256、分支当前采样、源授权与签名交付声明。它**不接受**来自请求或历史 JSON 的 `eligible=true` 自报。只有 EC203 返回所有选定 repository 文件均与签名 target 的 blob 一致、存在至少一个选定 repo 文件时，才进入旧基线对比。

基线另需**宿主独立配置**的 Ed25519 公钥（与当前 target 交付公钥分离的信任角色）、另一份绑定精确请求/期间/目标签名声明/旧新 full OID 的签名历史基线声明，以及 EC204 完整 scope/来源/上游两张政策/双签名信任注册表的独立只读政策。假签名、未知 key、旧新 OID 不一致、不存在或非祖先 Git commit、权限欠缺、ref 被移动/仓根漂移均**不能**产生已比较的变更结论。

满足以上条件后，只检查用户**预先逐项授权**的至多32条 EC202 选定仓库相对路径，并真实读取两个固定 commit 的 Git `ls-tree` 与 blob 字节、核实 blob Git OID；比较 SHA256 和可执行位，输出：

- `MODIFIED`：两端都是普通 Git blob、实际字节 SHA256 不同；
- `ADDED`：旧 commit 中该路径不存在、新 commit 中存在已核实 blob；
- `MODE_ONLY`：字节相同，仅 Git 100644/100755 模式改变；
- `UNCHANGED`：两端该路径的 Git blob 字节与模式都相同；
- `UNKNOWN`：源许可不足、签名/祖先无效、基线含 Git symlink/submodule、不可读取、ref/root 漂移等。`REMOVED` 是未来兼容的枚举，但本轮 **EC203 需要所有选定文件在当前目标有实际字节匹配**，因此对目标中缺失路径只返回 `UNKNOWN`，**绝不虚报已证实删除**。

所有结果只证明**所选路径上的提交间字节/模式差异**。即使所有选定仓库路径可比，也始终有 `whole_repository_change_set_complete=false`、`knowledge_impact_state=UNKNOWN_REQUIRES_EC205_SECTION_MAPPING_AND_REVIEW`、`knowledge_sections_to_update=[]`、`verified_delivered_facts=[]`。不扫描未选择文件，也不因某个文件变化而推断必需改动哪一章。EC202 的 manifest 未读/不完整/未选及过期覆盖缺口、EC203 各来源缺口原样保留。

## 2. 调用方式与独立权限

```python
from knowledge_boundary import canonical
from knowledge_impact import KnowledgeImpact

# 所有根路径、逻辑仓身份、目标 ref、target/baseline 公钥由可信宿主独立配置。
impact = KnowledgeImpact(
    repository_root='/host-configured/repo',
    knowledge_root='/host-configured/ces-space',
    repository_ref='cesrepo1:' + '<real 64-digit logical repository ID>',
    target_ref='refs/heads/main',
    trusted_target_keys={'delivery-authority': target_public_key_raw_32_bytes},
    trusted_baseline_keys={'historical-baseline-authority': baseline_public_key_raw_32_bytes},
)
pins = impact.binding_preview(request_json=canonical(ec202_request))
# 可信授权器根据 pins 生成 3 个彼此分离的、同一请求下的只读政策：
# ec202_read_policy、ec203_target_read_policy、ec204_impact_read_policy。
# 同一可信宿主提供签名的 EC203 target 与 EC204 baseline 声明。
result = impact.analyze(
    request_json=canonical(ec202_request),
    bootstrap_read_policy_json=canonical(ec202_read_policy),
    target_read_policy_json=canonical(ec203_target_read_policy),
    impact_read_policy_json=canonical(ec204_impact_read_policy),
    target_statement_json=canonical(signed_ec203_target_statement),
    target_signature_base64=target_signature,
    baseline_statement_json=canonical(signed_ec204_baseline_statement),
    baseline_signature_base64=baseline_signature,
)
# result['status'] == 'partial' and result['exit_code'] == 2 for bounded observations;
# no positive result has knowledge section-update authority.
```

**EC204 自身读政策（严格合约）**见 [schema](knowledge-impact-read-policy.v1.schema.json)。`purpose=knowledge_impact_read_only`，`permit_impact_read` 和 receipt 必需；基线签名验证、Git 旧提交读取、selected-path compare、单条 source 比对、SHA/mode 可见性逐层独立授予。所有来源授权按原 EC202 source_key/source_binding 顺序完整绑定，且只可对 `repository`（非 `ces_knowledge`）授予 `permit_baseline_path_compare`。比对授权还要求原 EC203 `permit_git_blob_compare`；SHA/mode 结果的展示还要求原 EC203 `permit_source_digest_projection`，未允许时值为 null。五种写入、Issue、发布许可必须全部为 false。

政策还绑定原 EC202 request/scope、两个 POSIX 根与 Git inode pin、host target ref 公钥配置、单独 baseline 公钥 registry、**完整 EC202 与 EC203 读政策摘要**以及 EC203 target 签名声明摘要。任何重放或变更会被拒绝。**receipt SHA 是绑定字段而不是可信组织认证/授权签章**；调用方填写 `permit=true` 不赋予权限，只有宿主经过独立认证和审批后才可以配置该政策。

## 3. 历史基线签名合约

`knowledge-impact-baseline-statement.v1.schema.json` 严格要求下列字段且无扩展字段：

```json
{
  "schema": "ces.knowledge_impact_baseline_statement.v1",
  "purpose": "knowledge_preceding_delivered_commit",
  "signer_key_id": "historical-baseline-authority",
  "repository_ref": "cesrepo1:<real-64-hex>",
  "knowledge_space_key": "architecture",
  "source_policy_revision": "policy-v1",
  "period_id": "oct-2026",
  "request_binding_sha256": "<from EC204 pins>",
  "scope_binding_sha256": "<from EC204 pins>",
  "target_statement_binding_sha256": "<CES-EC204-TARGET-STATEMENT-v1 domain digest of full EC203 statement>",
  "target_ref": "refs/heads/main",
  "baseline_revision": {"algorithm": "sha1", "oid": "<real baseline commit OID>"},
  "target_revision": {"algorithm": "sha1", "oid": "<real EC203 target commit OID>"},
  "baseline_recorded_at_utc": "2026-10-10T12:00:00Z"
}
```

上面尖括号是**说明性占位符，非合法可通过的值**。签名使用：

```python
payload = b'CES-EC204-BASELINE-ATTESTATION-v1\0' + canonical(statement).encode('ascii')
# baseline_signature_base64 = base64.b64encode(org_authorized_baseline_signer.sign(payload)).decode('ascii')
```

必须使用**独立签名且已通过宿主实际组织权限与撤销检查**的基线提供者；模块只验证它属于宿主配置的公钥，无法单独证明该 signer 的组织职权或真实历史交付事件。`baseline_recorded_at_utc` 必须早于所核验 EC203 签名 target 的 `delivered_at_utc`，基线 SHA/算法必须是**真实且已核实的 Git commit**，并经实际 Git `merge-base` 检查为目标祖先。相似 patch、同名 branch、PR head、提交消息、工作区 SHA、自签公钥都不替代此路径。

## 4. 输出、错误和界限

[Result Schema](knowledge-impact-result.v1.schema.json) 验证 `binding_preview` pin 和 `analyze` 结果的 `canonical_json` 与 `subject`。无误但是证据有限时永远为 `partial/2`；无法授权/绑定为 `unavailable/5`；结构非法为 `invalid_input/4`。`summary` 明确区分已比较文件数、变化数、不可确定数和**整个仓库与章节并未验证**，并且不回显签名、原始代码/知识正文。

即使 target 签名与旧基线都有效，只能说**宿主允许访问的本地 Git 对象和两份 host-key 验签对上了**，不能证明组织实际 key 发行、签名权限/撤销、实际部署、Provider 变更历史、旧章文档当前真实性、完整仓库所有改动、自动语义关联或应修订章节。EC205 才进行已有章节关联与差异，EC206 才做候选隔离，EC208 才做版本化保存。不存在原生 PowerShell KnowledgeImpact 路由或写操作。

环境依赖 POSIX nofollow 文件读取、宿主 Git 可执行文件以及 Python `cryptography` 的 Ed25519 验证。EC202 最多32源，每源16KiB、累计256KiB；EC204 历史基线 statement 最多8KiB、政策最多64KiB、Git commit 上限128KiB、单条 blob 16KiB、Git 子进程 4 秒/有界输出；永不运行外部网络命令、hook、fetch/push、业务源码、知识库、Issue 或报告的写入。验证真实组织授权/撤销、Git供应链/存储风险、ref竞争、多OS/文件系统和 PowerShell7/15 Smoke/E63–E66/最终验收统一记作 `NOT_RUN`，缺失原冻结计划 B-001 继续 OPEN。
