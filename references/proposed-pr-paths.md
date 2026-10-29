# EC-163 — ProposedPR文件路径元数据（独立只读Python工具）

**施工包V4.73/R163** · [功能模块](../construction/proposed_pr_paths.py) · [机器接口](proposed-pr-paths.v1.json) · [本轮记录](../EC-163.md)。仍**不是**PowerShell原生`Collect -Mode ProposedPR`；主CLI内置V4.60/R150及CodeSave权限链没有变化。

## 可做什么

- 基于一次**已有的EC162完整JSON pin**，分别在获取路径清单**前后**重新调用EC161的单GET元数据源，重算并逐字段匹配EC162不变仓/提议ID、base/head/target-tip完整SHA、fork和状态；两次都须匹配先前pin，且变更文件数量及其可靠性等级必须保持一致。否则`unavailable/5`，`files:[]`，绝不回传可能过时的路径。
- GitHub采用`GET /repos/{owner}/{repo}/pulls/{number}/files`、GitLab采用`GET /projects/{project}/merge_requests/{iid}/diffs`（不使用已弃用`/changes`），接收`per_page`/`page`的1..30页，只生成严格白名单路径/重命名旧新端/状态及可证实的增删统计。GitHub有数值`additions`/`deletions`/`changes`；**GitLab diff列表没有独立的增删统计，返回null而不是从补丁文本估算**。大文件`too_large`/`collapsed`仅登记文件级受限标志。
- 限制文件路径为不含绝对路径、`.`/`..`、反斜线、控制符/双向不可见控制、设备名及大小写折叠冲突的有界相对路径。完全不将Provider路径拼接成本地磁盘路径，也没有Git fetch、Issue/远程写、CodeSave权限或业务代码更改。
- `coverage.state`独立区分`COMPLETE`、`INCOMPLETE`、`UNKNOWN`及`NOT_COLLECTED`；GitHub文件列表接口最多3000项，碰到该上限不声称完整；GitLab的`changes_count`是异步数字字符串，`1000+`代表被封顶而非精确1000，欠缺数量即无法宣称完整。还要验证所有页路径去重、Provider数量与当前分页一致才可能`COMPLETE`。

## 调用

先在明确许可的安全环境获得EC162先前完整结果；**不要手写pin、不要用无凭据的fixture冒充线上认证结果**。

```bash
cd ces
# 以下命令没有 --allow-network，不访问任何Token或网络；返回 unavailable/5。
python construction/proposed_pr_paths.py --provider github --repository owner/repo --number 12 --expected-pin /safe/previous-ec162.json --json

# 安全环境中预先单独注入 CES_GITHUB_TOKEN；仅显式开启只读API GET。
python construction/proposed_pr_paths.py --provider github --repository owner/repo --number 12 \
  --expected-pin /safe/previous-ec162.json --allow-network --per-page 100 --max-pages 30 --json

# GitLab.com：预先注入CES_GITLAB_TOKEN；多层group/project路径可用。
python construction/proposed_pr_paths.py --provider gitlab --repository group/subgroup/project --number 8 \
  --expected-pin /safe/previous-ec162.json --allow-network --json
```

先前JSON来自`python construction/proposed_pr_identity.py ... --allow-network --json`；必须匹配**同一Provider、目标仓路径和提议编号**，已变更的不变ID或SHA会导致本轮直接拒绝。一个pin摘要只是可重算的本地SHA-256指纹，**不是数字签名/服务器身份认证**。保存输出需由调用方自行在受控目录完成，工具不写文件。

## 分页和截断逻辑

- 只有**前后两次EC162 pin一致**、变更文件数量声明均一致且是精确数值、所有请求页终止、已收到唯一有效路径总数与声明相等，才可将路径元数据标记`COMPLETE`。若服务端提供分页总数信息，还须与实际计数一致。
- 页数不足、超过文件数限制或字节上限：保留已确认的有限列表，标`partial/2`与`INCOMPLETE`。遇到网络/权限失效、状态冲突、异常分页链接、修改中的base/head、数量跳变、重复路径或穿越路径则`unavailable/5`且**不给出路径**。一个空第一页不会自动变成“没有变更”。
- GitLab `changes_count`缺失/尚未计算：`UNKNOWN`；`1000+`：`INCOMPLETE`；即使GitLab`collapsed/too_large`仅表示单文件补丁无法展开，也不会凭此补齐其它文件。GitHub的3000项上限永不被包装成“恰好全部变更”。
- **真实Provider是否持续提供这些字段，尚未在线验证。** GitLab部分环境可能不发完整分页头；模块只从允许的固定API路径按确定的页码读取，不跟随外部Link地址，矛盾头部fail-closed。

## 敏感内容的真实边界

两个Provider的文件列表接口自身可能把补丁文本放进JSON：GitHub的`patch`、GitLab的`diff`。**EC163不会请求单独的raw patch API，也不会返回、记录、落盘、保存或分析这些补丁字段**，只从接收的JSON提取路径白名单。由于Provider自身返回这些字段，不能承诺“补丁字节完全不经过内存/网络”；需要主动请求或展示敏感补丁文本的功能留给**EC164**独立授权开关。

服务器响应最多2MiB/页，累计12MiB，最多30页、100文件/页、3000文件，单次GET超时1..30秒；默认**禁网**。TLS校验，禁止隐式代理、HTTP重定向、自动重试、非GET或任意Provider域名。输出只包含受限文件路径元数据，不回显响应正文、token、外部URL或底层异常文字。

## 状态及后续

`success/0`仅在**真实而非合成**的两次pin检查、精确数量与页终止一致时代表“本次受限列表覆盖了Provider声明的路径数”；并非跨页原子diff快照，亦非变更未发生、仓库来源认证、PR已合并/已部署或可写授权。合成数据即使分页完整，顶层也只能`partial/2`且`synthetic:true`。真正稳定的可重现diff版本、分页并发一致性与Content SHA绑定属于**EC165**；EC164仅负责补丁敏感内容的单独选择。

开发时本轮聚焦Python模拟/契约用例可在没有Token的离线环境使用，不等于GitHub/GitLab真实API验收；PowerShell7、15个既有Smoke、Windows/macOS/Linux、E63–E66与最终联验继续`NOT_RUN`。

Provider官方参考：[GitHub PR files](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests-files) · [GitLab MR diffs](https://docs.gitlab.com/api/merge_requests/#list-merge-request-diffs) · [GitLab分页规则](https://docs.gitlab.com/api/rest/#pagination)。


## 后续EC164施工状态（V4.74/R164）

本文件保留EC163历史交付时“EC164计划中”的范围描述，不代表当前EC164未做。EC164已在独立[`proposed_pr_patch.py`](../construction/proposed_pr_patch.py)添加**默认不返回patch**的敏感内容开关，只在显式网络/权限确认、精确路径、预算与EC163完整路径结果/EC162前后pin满足后释放受限文本；使用方法见[`proposed-pr-patch.md`](proposed-pr-patch.md)。EC163原`ces.proposed_pr_paths.v1`输出及默认隐私边界继续不变；EC165跨页版本一致快照仍未实现。
