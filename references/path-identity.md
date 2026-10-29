# CES EC-159 — 本地工作目录、仓库根路径与外部 actor 身份

> 接口位于 `scripts/pathidentity.ps1`，由主 `scripts/ces.ps1` 在 `Git-In` 定义之后从受信的 Skill 目录加载。**它不是新CLI Action**，不新增写权限、网络访问或认证Provider。施工包 V4.69/R159，内置CLI依旧V4.60/R150与`ces.cli.v1`。

## 1. 四种不同对象，永不混用

| 对象 | 输入及解析 | 可得结论 | 不可得结论 |
|---|---|---|---|
| 用户选定 `RepoPath` | `Resolve-CesUserPath -Path ... -RelativeTo ...`，绝对/相对均允许 | 仅把显式路径规范化，标明来自使用者 | 仓库身份、主体认证、写权限 |
| Git worktree | 原`Inspect-Repository`读取`rev-parse`、`HEAD`，用共用`Read-CommonGitDirectory`/`Find-VerifiedStableRoot` | 主/linked/unverified/bare分类与来源根；基于main `.git`三重验证 | Git仓库能证明Git作者或真实远程组织身份 |
| **安全可用的main根** | `Assert-CesVerifiedMainWorktree -GitExecutable ... -RepoRoot <absolute>` | 单次调用中，独立复查`bare/inside/top/absolute-git-dir/common-dir`、严格主根和路径同一性、祖先reparse拒绝；返回`stable_root_verified:true`、临时主root与`repo-local-...`键 | **不是写入授权**；不能保证无并发替换；本地键不能跨机器/迁移/clone认同仓库 |
| 外部actor | `Resolve-CesActorIdentity -Provider <namespace> -Tenant <scope> -ImmutableSubjectId <opaque>` | 缺ID=`unknown`、不完整/无效拒绝、完整tuple=`declared_unverified`；只返回`actor-claim-...`本地不可逆分组键 | 不能根据display name/Git author/email猜识别；tuple即使完整也**不自动认证**，`actor_key:null`、`verified:false`、不可授予写权限 |

### Main根验证必须是独立交叉检查

- `git worktree list`的第一行、名称匹配或源路径字符串均不是证明。要求common-dir basename严格是`.git`候选，且候选main内`--show-toplevel`、`--absolute-git-dir`、`--git-common-dir`三向同一。
- 对可能写入/读取CES存档的主根，另外检查当前源本身必须是main，不是共享common-dir的linked worktree；检查Git输出规范路径的**准确大小写**，拒绝混入大小写别名作为存储主根；检查根及Git目录所有现有祖先的reparse属性。
- `repo-local-...`只用于识别**当前机器此路径的本地仓库上下文**，来自common-dir全路径的领域分隔SHA256。它不会进入v1存档，也不是Git object ID、全局仓库ID、远程URL身份证明、稳定跨迁移标识。
- `Get-CesScopedOpaqueKey`采用UTF-8、4字节大端长度前缀与SHA256，避免组分连接碰撞；摘要不可当作提供者签名或授权令牌。

## 2. 路径和证据读写规则

- `Normalize-FullPath`保留原PowerShell API签名与一般有效路径的词法规范化行为；`Paths-Equal`保留v1兼容比较规则。**字符串相等并非inode/文件句柄认证**。外部actor只能来自外部实际不可变主体ID、租户/来源，并需要**未来独立Provider验证器**才能升级为verified；当前对所有actor的`Assert-CesVerifiedActor`一律阻断。
- `Assert-CesContainedPath`只服务**受信绝对Root下面的受限本地路径**：拒绝所有`..`路径段、精确根自身（除非显式`-AllowRoot`）、绝对越界、`/repo`对`/repo-sibling`前缀混淆、符号链接/Windows junction或其它reparse祖先。Windows/macOS按忽略大小写检查**包含关系**（仅保守边界），后续原有CodeSave的Git索引/HEAD及额外目标SHA路径大小写碰撞扫描不可省略。
- `Resolve-CesEvidencePath`允许调用方有意把Collect JSON或草稿放在仓库之外，但只把其作为**未认证的只读字节**，已有文件和祖先必须无reparse；原`Read-ReconcileSnapshotFile`/`Read-CodeValidateDraft`仍负责有限长度、UTF-8/SHA/结构校验。证据SHA属于所读字节摘要，不证明来源可信或写权限。**不能用RepoPath根的包含规则禁读用户明确放在仓库外的证据**。
- CodeSave在已明确`-ApprovePersist`并完整CodeValidate/Reconcile后，复查main根、原有Git/index/HEAD/pinned target存储空间门禁，初始化固定`.codex/ces/...`路径时复查path/reparse，并在最后的no-clobber写入前再复查main与Git边界。CodeShow读取本地存档同样复查main根和固定存储路径。没有把新身份对象写入旧record JSON或改变CLI包络。
- `Assert-CesNoReparseAncestry`检查**每个已存在**的祖先，不把普通缺失的计划新建叶子误认为链接；访问被拒/未预料I/O失败一律拒绝。单次路径查询与接下来的open/move不是原子事务。恶意并发替换/大小写卷特例、重定向的挂载及Git仓内不可信配置仍有残余风险；最终需要OS handle-relative实现或隔离环境级保证，**不能把本轮宣称为彻底TOCTOU修复**。

## 3. 日志与身份防冒认

`Format-CesPathForLog`返回`<verified-repo-root>`、`<inside-verified-repo>`或`<external-or-unverified-path>`，不返回绝对路径/文件名；`Redact-CesKnownPaths`按字面、最长优先替换已知路径用于界限明确的旧异常消息，不解释正则。CodeSave/CodeShow存储安全失败会先做已知路径脱敏再把诊断放进原有限字数`warnings`。这不是万能secret scanner，不能把用户提供的任意JSON、Git输出或异常文本直接当安全日志。

下面示意直接dot-source后手工使用（非新CLI参数，需在真实 PowerShell7 下执行）：

```powershell
. ./scripts/pathidentity.ps1
$selection = Resolve-CesUserPath -Path './my-repo' -RelativeTo (Get-Location).ProviderPath
# 只有已有的Git-In（由主CLI定义）可供下一调用使用
# $stable = Assert-CesVerifiedMainWorktree -GitExecutable '/usr/bin/git' -RepoRoot $selection.absolute_path
$actor = Resolve-CesActorIdentity -DisplayName 'Alex'
# status=unknown, actor_key=$null, can_authorize_write=$false
```

## 4. 兼容性与最终统一验收

- **保持**七个CLI Action/16路由/29未实现能力、v1响应16顶层字段/31 coverage、原`CodeInsight`SHA存档、CodeShow Sequence k1..56、R150冻结hash和EC157审阅收据。
- 行为更严格的地方：main `.git`/任意父目录reparse或Git路径大小写别名会导致stable root不可信；通过符号链接目录读取证据会拒绝；已保存记录若只有symlink别名入口，则应从实际main根重新读取，**不可提升该别名权限**。
- 原生需要人工协助的场景见`tests/PathIdentity.EC159.ps1`：相对/绝对/越界与前缀碰撞、symlink（系统许可时）、缺/同名actor、多租户、main/linked worktree及授权缺失时无本地写盘。再统一运行原15个Smoke、EC157安全场景、Windows/macOS/Linux Git交互/恶意竞态、E63–E66真实性能，均在总功能完成后验收。
- **本包未运行上述PowerShell本机用例**：缺`pwsh`及跨平台环境；只做必要的文档/源代码对齐检查，不把静态检查冒充原生安全验证。
