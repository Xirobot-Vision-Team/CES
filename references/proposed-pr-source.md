# EC-161 — ProposedPR 只读来源适配器（独立 Python）

实现入口：[`../construction/proposed_pr_source.py`](../construction/proposed_pr_source.py)；机器契约：[`proposed-pr-source.v1.json`](proposed-pr-source.v1.json)；施工记录：[`../EC-161.md`](../EC-161.md)。**这是实装的独立来源适配器，不是原生 PowerShell `Collect -Mode ProposedPR`。** 旧 CLI 对该模式仍 `NOT_IMPLEMENTED`；输出自有`ces.proposed_pr_source.v1`，不能假扮`ces.cli.v1`或直接交给CodeSave。

## 用法：默认不联网

```bash
# 缺少 --allow-network，不查看环境密钥、更不会创建PR对象：unavailable/5
python construction/proposed_pr_source.py --provider github --repository owner/repo --number 12 --json

# 由调用环境的秘密管理工具注入 CES_GITHUB_TOKEN 后，单次只读HTTPS GET
python construction/proposed_pr_source.py --provider github --repository owner/repo --number 12 --allow-network --json

# GitLab 支持 group/subgroup/project；环境变量 CES_GITLAB_TOKEN
python construction/proposed_pr_source.py --provider gitlab --repository group/subgroup/project --number 7 --allow-network --json
```

**绝对不要把 token 放进命令行参数/版本库/收据。** CLI 无`--token`选项；标准库`os.environ`按Provider读取`CES_GITHUB_TOKEN`/`CES_GITLAB_TOKEN`，也能在嵌入 Python 时使用`token_supplier=lambda: ...`（调用方自己负责取密钥）。没有密钥或仅提供无效密钥→`unavailable/CREDENTIALS_UNAVAILABLE/5`；被Provider拒绝→`unavailable/PROVIDER_AUTH_UNAVAILABLE/5`；离线模式→`unavailable/NETWORK_NOT_AUTHORIZED/5`。两项同时欠缺时优先报`NETWORK_NOT_AUTHORIZED`，不去试读凭据。

## 网络、来源、字段限制

- 仅允许 `api.github.com` 的 `GET /repos/{owner}/{repo}/pulls/{number}` 和 `gitlab.com` 的 `GET /api/v4/projects/{encoded group/project}/merge_requests/{iid}`。用户只能传路径片段/整数，**不能给任意URL、scheme、host、端口或跳转地址**；不支持企业自托管、其他Provider。本EC明确接受窄范围而非任意连接来降低SSRF/密钥出站风险。
- 只有显式`--allow-network`才进入鉴权；已固定验证证书的HTTPS、屏蔽隐式系统代理、拒绝所有3xx跳转，不做自动重试；每次最多1个请求，超时默认8秒（上限30秒），响应体上限1MiB，不跟进分页、patch/files/commit列表或merge/ref修改URL。HTTP GET可能在Provider内部触发mergeability的异步计算，但本代码不执行远程写操作。
- 对JSON按UTF8完整解析，拒绝重复键、NaN、非对象根、异常MIME类型/长度；输出**白名单**仅承载所需编号、服务端ID声明、状态、base/head完整40或64位SHA、SHA语义与来源/未认证状态。丢弃标题、正文、作者、路径、patch、tokens、原始响应和错误body；失败码/消息不拼接Provider异常或请求头。
- GitHub只承认`base.repo.full_name`与请求仓名不区分大小写相同、`number`一致时的**候选**字段；`base.sha`是基础分支当前tip，而不是一定代表merge-base。GitLab只承认`iid`一致、`target_project_id`、`source_project_id`存在、`diff_refs`当前有base/head/start完整SHA、顶层`sha`如存在与`diff_refs.head_sha`一致；`diff_refs.base_sha`**是merge-base**，不是target分支tip。GitLab刚创建的MR可能异步暂时没有`diff_refs`，此时返回`PROVIDER_METADATA_INCOMPLETE`，不能从分支名猜SHA。
- 远端`id`、`target_project_id`及SHA值仍只属于Provider本次响应内的**未经独立认证的声明**，既不与本地`.git`对象或用户账号身份交叉证明，也不与远程不变版本或实际交付绑定。真实源可能在请求后立刻变更；EC162另提供可调用的来源pin对比与只读Git对象核对，不会把本v1元数据`success`自动变为身份认证。`provider_reports_merged`只是远端布尔/状态自述，**`delivery_or_merge_proven`始终false**。

## 响应与拒绝

统一JSON根字段 `schema/status/reason_code/exit_code/message/source/synthetic/native_cli_action_registered/write_authorized`。离线或错误时`source:null`，不产生可误当PR的“默认对象”；非法输入`invalid_input/4`，不可访问/无密钥/网络/字段不完整`unavailable/5`。仅真的读取到符合有限字段契约的Provider响应时才`success/0`；此处`success`**只指一次受限元数据读取，不代表PR身份绑定、diff快照认证或真实合并交付**。

测试中使用显式注入的传输器必返回`synthetic:true`和`source.origin:synthetic_fixture`；两份fixture在[`../construction/fixtures/README.md`](../construction/fixtures/README.md)注明全部伪造。用模拟传输对象得到`success/0`也不可称真实联网成功。正常CLI不支持输入fixture替代远端。出于谨慎，源码允许的`_ces_fixture`标记在正常HTTPS返回时会强制拒绝。

下列不是本EC161入口工作：EC162身份/SHA事实约束已在独立[`proposed_pr_identity.py`](../construction/proposed_pr_identity.py)实现（见[`proposed-pr-identity.md`](proposed-pr-identity.md)），不改变此处的metadata-only身份级别；EC163文件状态和更名清单、EC164敏感patch开关、EC165分页/快照、原生`Collect:ProposedPR`集成、外部账号actor认证、远程写、Issue/Delivery。所有旧CodeSave授权依然由原CLI掌管，任何来源响应都不得授予它写资格。


## EC-162增强的元数据最低门槛（V4.72）

在保持此入口`ces.proposed_pr_source.v1`、三种原状态、单GET和“不授权”的前提下，EC162为下游pin工具增加了**必需的源仓库不可变ID**：GitHub `head.repo.id`及经格式约束的`head.repo.full_name`（同一响应的repo ID相等关系必须与完整路径相等关系一致），GitLab `source_project_id`、`diff_refs.start_sha`（以及可用时`project_id`/`references.full`交叉检查）。缺少源fork仓、GitLab start_sha或发现字段冲突，返回`unavailable`，不从branch名、合成ref或PR编号回填。输出新增`provider_source_repository_id`/`provider_source_repository_path`，GitLab另外提供`target_tip`。旧EC161的`identity_binding: NOT_VERIFIED_EC162`字段作为**历史兼容标签**保留；只有单独运行EC162工具才会计算和复核pin，且仍不提供diff快照与写资格。源码提交期真实端点仍未访问。

## 有限开发检验及延后项目

可在无联网、无Provider凭据下运行`python construction/test_proposed_pr_source.py`，测试注入的**合成**GitHub/GitLab响应、fail-closed、输入约束、路径编码、密钥不可泄漏和离线CLI退出码；这不能替代真实网络和主PowerShell入口、15套Smoke、Windows/macOS Git、E63–66或最终人工验收。本轮没有调用任何真实Provider；如用户最终提供可信运行环境/凭据再统一验收。

官方字段依据： [GitHub Get a pull request](https://docs.github.com/en/rest/pulls/pulls) 、[GitLab Retrieve a merge request](https://docs.gitlab.com/api/merge_requests/)。GitHub请求使用文档当期REST版本`2026-03-10`；如果Provider以后停止支持，应由后续兼容施工显式升级，不偷偷降级证书、认证或端点限制。

## EC-163后续可选数量字段（V4.73；EC161功能语义不变）

为了给[EC163路径清单消费者](proposed-pr-paths.md)提供完整/截断判定，`_proposal_from_github`/`_proposal_from_gitlab`在**不触及EC162封闭pin字段**的情况下增加两个白名单输出：`provider_reported_changed_files`（精确非负整数或null）和`provider_change_count_quality`（`EXACT_PROVIDER_CLAIM`、`NOT_REPORTED`、`CAPPED_PROVIDER_CLAIM`、`CAPPED_OR_UNEXPECTED_PROVIDER_CLAIM`）。GitHub来自GET PR的`changed_files`，GitLab来自GET MR的`changes_count`，其中空值代表异步未生成，`1000+`代表封顶，**不表示刚好1000**。类型伪造拒绝，而不会默认为0。原`ces.proposed_pr_source.v1`根Schema/状态/退出码和单GET约束不变；单次元数据源无权宣布文件路径清单完整。EC163另行调用多页文件列表，要求先前EC162 pin及前后两次一致，见专用说明。
