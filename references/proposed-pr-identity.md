# EC-162 — PR/MR不可变身份与base/head事实绑定（独立Python）

**当前施工包：V4.72/R162。** [可执行入口](../construction/proposed_pr_identity.py) · [机器契约](proposed-pr-identity.v1.json) · [EC-162施工记录](../EC-162.md)。依赖[EC-161元数据源](proposed-pr-source.md)，但返回单独的`ces.proposed_pr_identity.v1`，没有加入PowerShell旧的`ces.cli.v1`和`Collect -Mode ProposedPR`路由。**任何输出都不是写许可。**

## 实际功能

EC-162把“项目路径+PR编号”从**可变定位符**降为只用于访问接口的定位信息。每次只使用EC161的一次固定HTTPS metadata GET（默认断网），从响应中提取并核对：

| 事实 | GitHub PR | GitLab MR |
|---|---|---|
| 目标仓库不变ID | `base.repo.id` | `target_project_id`（如果有`project_id`还需一致） |
| 来源仓库不变ID | `head.repo.id`；fork删除后为null则拒绝 | `source_project_id`；缺失则拒绝 |
| 提议不变ID | PR `id`（不是`number`） | MR `id`（不是项目内`iid`） |
| base完整OID | `base.sha`，**目标分支tip** | `diff_refs.base_sha`，**合并基点** |
| head完整OID | `head.sha`，源分支tip | `diff_refs.head_sha`，该diff版本head；顶层`sha`存在时必须相同 |
| target tip | 与`base.sha`同一个事实 | `diff_refs.start_sha`，**该diff版本**目标commit，未必是查询时最新target tip |
| fork/改名 | 用`head.repo.id`判定fork，用合法`head.repo.full_name`登记当前源路径 | 用`source_project_id`判定fork；不根据branch推测项目ID |

OID只接受40位SHA-1或64位SHA-256十六进制（同一提议内长度必须一致），拒绝短哈希/全零/混合算法。分支名、`refs/pull/N/head`、`refs/merge-requests/N/head`以及本地`HEAD`都不能代替完整OID。单GET各字段仍是**Provider在观察时的自述**，不是含证书/签名的跨时间事实，也不是经独立认证的全球仓库来源。

## 使用（显式许可网络/从不保存token）

```bash
# 只执行拒绝路径；不用任何token、不联网：unavailable/5
python construction/proposed_pr_identity.py --provider github --repository owner/repo --number 12 --json

# 在外部安全环境事先注入 CES_GITHUB_TOKEN 后，单次只读获取候选pin
python construction/proposed_pr_identity.py --provider github --repository owner/repo --number 12 --allow-network --json > first.json

# 稍后重新读取Provider，严格比较原pin；可选择本地Git只读核对
python construction/proposed_pr_identity.py --provider github --repository owner/repo --number 12 --allow-network --expected-pin first.json --local-git /absolute/path/to/approved/clone --json

# GitLab使用CES_GITLAB_TOKEN；可填group/subgroup/project
python construction/proposed_pr_identity.py --provider gitlab --repository group/subgroup/repo --number 8 --allow-network --json
```

`first.json`由**调用方自行重定向到安全私有位置**，CLI不自动写文件、不会保存token；`--expected-pin`只接受之前完整的EC162 JSON输出（最大64KiB），不是`ces.proposed_pr_source.v1`、不是任意SHA字符串。输入JSON拒绝重复键/非有限数字/格式变化；以来源路径、Provider项目ID、PR全局ID、源项目ID、fork关系、base/head/target tip全长OID、状态、算法、语义和live/synthetic标签做严格对比。

- **没有前次pin：** 返回`partial/2`和可供人工保存的受限候选pin，明确`NO_PREVIOUS_PIN`；即使本地对象存在，单次Provider快照也无法证明持续稳定。
- **两次Provider字段相同，但没有本地Git核对：** 返回`partial/2`。即使两个响应一致，接口之间仍可能变更，并不提供原子快照。
- **预期pin漂移：** 返回`unavailable/5`、`pin:null`，`PIN_DRIFT_*`给出优先原因与`changed_fields`字段名。更换仓ID/PR全局ID、fork源ID、仓路径迁移、head变化（包含正常push或force-push）、base/target变化、合并状态变化都让旧pin失效，**不能盲目继续处理**；必要时在人工审查后不带`--expected-pin`重新建立候选。
- **Git对象核对不全/不可用：** 返回`partial/2`，不伪造commit存在。只有两次相同、**非合成**的Provider响应，并且所请求的本地Git对象均确认为`commit`时，返回受限的`success/0`，仅表明“跨两次元数据响应一致+这些OID确实在指定的本地对象库”，不代表该对象确实来自目标Provider项目。
- **模拟传输**永远`synthetic:true`，即便两次相同且本地存在OID也不返回真实源等级的`success`。

### SHA与hash边界

`pin_fingerprint`是带域分隔前缀的SHA-256规范化JSON摘要，用于**检测偶发修改和比较**；持有者可重新计算，它不是数字签名、远端认证、封存快照、代码审查结论或“已部署”证据。返回`pin`只包含固定白名单字段，不回显title/body/author、路径清单、补丁、原始响应或任何密钥；GitHub/GitLab `provider_reports_merged`不提升`delivery_or_merge_proven`（始终false）。

### 可选本地Git核对的明确上限

使用`--local-git`必须显式提供**绝对目录**。实现只运行一次`git --no-optional-locks -C DIR cat-file --batch-check`，按stdin输入固定完整OID，要求所见对象类型为`commit`；不运行Git网络fetch/checkout、分支解析、hook或索引/工作树修改。为避免partial clone自动取对象，关闭Git lazy fetch/远程协议，清除继承的Git相关环境覆盖、禁用replace objects和全局系统配置；超过5秒/缺Git/缺对象/返回异常均只能称未核对成功。**本地Git共享对象/alternates可包含其它项目对象**，所以“存在commit”仍无法证明repo归属或可靠远端快照。对于未知Git实现或环境该检查可能只会返回部分结果，不能降级为远程下载。

## 边界与后续

没有实现EC163的file status/rename/list、EC164 patch、EC165分页一致快照/ETag或PR被force-push后的原子快照；没有Issue、Delivery、provider actor认证、任何远程write、本地CodeSave权限提升或原生Collect路由。旧7个Action家族/16路由/29条未来未实装模式以及原PowerShell`V4.60/R150`均保持不变。

本轮仅使用[EC161的合成fixture](../construction/fixtures/README.md)及严格隔离的本地临时Git仓做有针对性的开发调试。**真实Provider API/凭据、Windows/macOS Git、PowerShell7原生、15套Smoke、E63–E66和最终用户联合验收均待最后统一进行**，不能把离线用例或两次自报当成真源证明。

Provider原始API说明：[GitHub Pulls REST](https://docs.github.com/en/rest/pulls/pulls)；[GitLab Merge requests API](https://docs.gitlab.com/api/merge_requests/)（其中`diff_refs`定义了base/head/start的不同含义）。

**后续施工状态（V4.73/R163）：** EC163已经在独立[`proposed_pr_paths.py`](../construction/proposed_pr_paths.py)与[路径清单接口说明](proposed-pr-paths.md)中实现GH/GL文件路径元数据及保守分页覆盖；以上“EC163尚未实现”仍是本EC162原交付时的历史范围说明，不改变原pin契约。EC164补丁开关、EC165原子diff快照及原生Collect仍未实现。
