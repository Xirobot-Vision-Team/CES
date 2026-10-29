# EC-165：ProposedPR 分页观测收据、版本范围与可选复读

当前施工包 **V4.75/R165**；独立 Python API/CLI：`construction/proposed_pr_snapshot.py`，返回 `ces.proposed_pr_snapshot.v1`。它在已有 EC161 元数据、EC162 identity pin、EC163 路径计数与分页、EC164 显式补丁门禁上完成**实际证据绑定功能**，但绝不把非原子 HTTP 观察升级成已证明的远端事务快照。主 PowerShell `Collect:ProposedPR` 仍 `NOT_IMPLEMENTED`。

## 核心能力及真实证据层级

1. **先校验再绑定**。调用者必须提交来自 EC162 的合法完整先前 JSON。每次 EC163 读取之前和之后重新比对相同 Provider 仓/对象 ID、base/head/target-tip 完整 OID、状态及文件计数；异常时没有 `observation_ref`、`evidence_material` 或已暂存补丁。只读调用限 GitHub.com `/pulls/{number}/files` 和 GitLab.com `/merge_requests/{iid}/diffs`，不跟随自报 URL、不读 branch/ref 内容、不写用户仓。
2. **单页有序观测记录**。对每页经过安全路径/rename/状态检查的**白名单文件元数据**计算域分隔 SHA-256；记录顺序页码、项数、下页、实际 HTTP 字节数、ETag 缺失/强弱状态及 ETag 的不可逆摘要、Last-Modified 是否存在。不输出原始 ETag/Last-Modified 字符串、未选中 `patch/diff` 或整页原始 body SHA。真正 HTTP body SHA 仅驻留内存供可选复读比较；供应商 JSON 可能夹带未授权披露的代码，不应将整个原始字节摘要变成可公开查询的相等性标志。
3. **收据绑定**。`evidence_material` 包含完整 EC162 pin、pin 指纹、两个元数据读取时间、EC163 覆盖事实、全部有序页摘要、受限请求分页和字节预算、精确文件选择、补丁输出预算/分类及经允许输出文本的 SHA-256（没有许可时连补丁 hash 也不生成）、可选的本地单文件版本核对、明确缺失的独立证据。`observation_ref=sha256(domain || canonical_json(evidence_material))`。`--verify-input` 用不联网的方法对同一 JSON 做交叉重算，报告 `INTERNALLY_CONSISTENT_ONLY`，不能验证外部 Provider 事实，攻击者可重算未签名的整个收据。
4. **可选复读 `--recheck-pages`**。首轮 *COMPLETE* 后用**同一个先前 pin**再做一次有界 metadata→page(s)→metadata 的独立观测。逐页对照页序、清洗路径字段、ETag 摘要、字节数和可获得时的原始 HTTP body SHA；显式开启 EC164 代码披露时，还比对所有已选补丁的可见内容 SHA/拒绝分类。任何读取失败、文件增减重排、ETag/raw-body SHA 变化、元数据 OID/count 漂移，都返回 `unavailable/5` 且**不返回初次已取得的代码或清单**。如果缺少原始 bytes 摘要，标为 `raw_response_comparison_unavailable`；不能把 mock 或受限页面的语义相等称为字节一致。一次是最多30页/12MiB，复读可能最多60页/24MiB（每次分别受限，默认不复读），且最多4次元数据只读 GET。
5. **限定的单文件版本**。可对不超过5条选中路径读取 GitHub `/files` 的 `sha`（Provider 声明的 blob OID，非认证映射）；不对未选中路径读取其他字段。可附 `--local-git /absolute/path`，只读执行 `git ls-tree -r -z <完整pinned head SHA> -- :(literal)<选中文件>`，禁止隐式 Git 配置/远端 lazy fetch/refs/checkout；仅普通 blob 模式 `100644/100755` 且文件路径精确匹配才记为 `LOCAL_HEAD_COMMIT_TREE_BOUND`。如果 GitHub 返回 blob SHA 而本地精确对象不一致，整次拒绝。它**仅能绑定给定本地对象库内的某一文件到给定 head commit**，不能凭本地 blob 证明这个 head 是 Provider 真实的版本、证明原远端 diff 包括了所有 hunks，或授权内容披露；删除文件不在 head 绑定。GitLab `/diffs` 没有同等稳定 blob OID 输出，须标未知或限本地对象检查。
6. **拒绝假完整**。只有 EC163 `coverage.state=COMPLETE` 才认为路径清单覆盖 Provider 当前声明；GitHub 3000 上限、GitLab `1000+`、provider count 未完成/缺页、封顶、预算不足保留 `INCOMPLETE/UNKNOWN`。完整清单不代表同一个不可变 diff snapshot；即使强 ETag 全部存在、两轮完全相同，也没有共享的跨分页事务/不可变 GitLab diff version ID。EC165 始终 `partial/2`，`diff_snapshot_proven=false`、`provider_atomic_snapshot=false`、`provider_immutable_diff_version_id=null`，不会输出“无其他变更”作为证据。缺版本ID/ETag为 `UNKNOWN` 层，不是已认证版本。

## 用法

```bash
cd ces
# 默认不联网；无 Token 仍能看到明确拒绝，不会生成虚假收据
python construction/proposed_pr_snapshot.py --provider github --repository owner/repo \
  --number 12 --expected-pin /approved/prior-ec162.json --json

# 只读路径/版本观测；须由用户提供合法最小权限Token与真实访问授权
# 环境变量 CES_GITHUB_TOKEN 或 CES_GITLAB_TOKEN 必须在安全环境中设置
python construction/proposed_pr_snapshot.py --provider github --repository owner/repo \
  --number 12 --expected-pin /approved/prior-ec162.json --allow-network \
  --path src/service.py --local-git /absolute/local/repository \
  --recheck-pages --json > /secure-directory/ec165-response.json

# 明确选择披露单个补丁文本：所有EC164权限开关依然强制
python construction/proposed_pr_snapshot.py --provider gitlab \
  --repository my-group/my-repo --number 9 --expected-pin /approved/prior-ec162.json \
  --allow-network --include-patch-content --ack-provider-content-permission \
  --path lib/service.py --max-patch-bytes 4096 --max-total-bytes 8192 \
  --recheck-pages --json > /secure-directory/authorized-private-response.json

# 离线重算包内JSON的内部一致性（不是Provider认证）
python construction/proposed_pr_snapshot.py --verify-input /secure-directory/ec165-response.json --json
```

代码内容披露由调用者主动选择、确认在对应 Provider 有访问/分享权限，并保护 stdout/文件所在位置；`--recheck-pages` 将实际请求翻倍，但不会绕开任何原 EC164 权限和补丁敏感内容过滤。`--local-git` 只读本地 Git 但本地对象库可能是不可信替身，不执行 checkout/pull/merge。

## 输出字段与失败分类

- `observation_ref`、`evidence_material`：仅当至少获得 EC163 有效路径数据后存在；字段中 `ordered_files_digest`、`ordered_pages[].sanitized_paths_digest`、`patch_disclosure.selected_patch_outcomes[].released_patch_digest` 可逐级重算。路径本身出现在下层 `patch_evidence.path_evidence.files`，明文补丁**只有**经过许可的 `patch_evidence.patches[].patch_text`。
- `version_consistency.state`：`NOT_ESTABLISHED`、`INCOMPLETE_OR_UNKNOWN_PATH_COVERAGE`、`OBSERVATION_ONLY_PROVIDER_VERSION_UNKNOWN` 或 `OBSERVATIONS_RECHECKED_NOT_ATOMIC`；后两者都不等于不可变 Provider snapshot。`missing_independent_proofs` 明列缺少Provider不可变diff版本及跨分页事务证据；`replay`区分是否执行、比较页数和是否缺少原始 body 比较。
- `selected_file_versions[].status`：`PROVIDER_BLOB_CLAIM_ONLY`、`FILE_VERSION_UNKNOWN`、`DELETED_PATH_NO_HEAD_BLOB`、`LOCAL_HEAD_COMMIT_TREE_BOUND` 或各类本地未查到/不可用。前者只为供应商声明，本地绑定也**不**认证远端作者/仓库归属。
- `SNAPSHOT_RECHECK_DRIFT_OR_UNAVAILABLE`、`SNAPSHOT_RAW_PAGE_CHANGED`、`SNAPSHOT_LOCAL_PROVIDER_BLOB_CONFLICT`、`PROVIDER_BLOB_OBJECT_FORMAT_CONFLICT` 一律 `unavailable/5`、证据为 `null`，不返回前次未验证片段。非完整但可安全列出的有限子集用 `INCOMPLETE_PATH_COVERAGE_RECEIPT` / `partial/2`，在任何意义上均不构成“差异已完备”。
- `verify_receipt` 仅做用户提供结果的内部一致性检查；没有签名、独立服务器确认或 HTTP 原始响应见证。攻击者可替换数据再重算 hash，完全不能用它作为审计/法律认证材料。

**环境与延期**：本轮开发使用合成 GH/GL fixture、mock transport 和隔离临时 Git；没有真实账号、Token、GitHub/GitLab 在线 HTTP、原生 PowerShell7/旧15 Smoke、Windows/macOS/Linux 跨平台、E63–66 性能、最终人工联验。累积这些检查到最终用户统一辅助验收。下轮 EC166 才处理**真正远程 Reconcile 再核对**。

官方字段语义参考：GitHub REST Pull Request files endpoint（3000条上限、可返回 blob `sha`）；GitLab Merge Requests `/diffs`（diff 限制、`collapsed`/`too_large`）及 `/versions/:id`（独立版本端点；**本轮不读取或证明**）。
