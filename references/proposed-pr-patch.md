# EC-164 — 独立只读ProposedPR补丁敏感内容开关

**施工包V4.74/R164** · [实现](../construction/proposed_pr_patch.py) · [机读契约](proposed-pr-patch.v1.json) · [聚焦开发用例](../construction/test_proposed_pr_patch.py) · [本轮记录](../EC-164.md)。不接入原PowerShell `Collect:ProposedPR`，不扩展CLI原有授权，不做远程写。

## 默认模式：路径元数据，不输出补丁

EC164始终复用EC163的完整先前EC162 pin、前后校验、固定只读GitHub PR `/files`/GitLab MR `/diffs`、逐页路径规范、数量/分页覆盖和所有拒绝语义。`--include-patch-content`不传时，**不会提取或返回任何`patch`/`diff`文字**；`patches:[]`、`patch_content_collected:false`。**联网也是独立开关**，不传`--allow-network`绝不使用Provider凭据。两家Provider文件列表API本身可能在JSON夹带diff文字，禁输出不等于网络传输/受限内存解析完全没有该字段。

```bash
cd ces
# 不联网、不能泄漏补丁；请使用此前确实从EC162取得的完整结果作为pin。
python construction/proposed_pr_patch.py --provider github --repository owner/repo \
  --number 12 --expected-pin /approved/previous-ec162.json --json

# 在安全环境预先注入 CES_GITHUB_TOKEN 后，仅显式读取只读路径元数据。
python construction/proposed_pr_patch.py --provider github --repository owner/repo \
  --number 12 --expected-pin /approved/previous-ec162.json --allow-network --json
```

## 独立内容许可+最小选择+预算

只有用户在本次调用**明确有权阅读并披露选定文件内容**时，才同时使用三个开关：`--allow-network`、`--include-patch-content`、`--ack-provider-content-permission`。此外必须使用`--path`逐个点名**1–5个**完整仓内相对路径（rename选新路径，删除选旧路径），不能用通配符/路径穿越，不接受疑似凭证路径。Provider令牌必须在外部安全注入，不能放进命令行。调用方确认的是自己具备访问/披露许可的声明，**程序无法独立验证业务合规授权**；HTTP成功不代表可以对外分享、也不代表身份认证或仓库写权限。

```bash
# 以下仅是接口示例；实际执行前必须由用户确认内容授权和输出保存环境。
python construction/proposed_pr_patch.py --provider github --repository owner/repo \
  --number 12 --expected-pin /approved/previous-ec162.json --allow-network \
  --include-patch-content --ack-provider-content-permission \
  --path src/only-selected-file.py --max-patch-bytes 4096 --max-total-bytes 8192 --json

# GitLab.com选择该MR文件的新路径；令牌为CES_GITLAB_TOKEN。
python construction/proposed_pr_patch.py --provider gitlab --repository group/project \
  --number 21 --expected-pin /approved/previous-ec162.json --allow-network \
  --include-patch-content --ack-provider-content-permission --path lib/new.py --json
```

默认每文件最多4096 UTF-8字节、总共最多8192字节；硬上限分别为8192/32768字节，1–5个路径。接入与数据上限继承EC163：1..100文件/页、最多30页、最多3000文件、2MiB/页与12MiB/总JSON、固定HTTPS域名、验证TLS、不跟随跳转/代理/Provider原始URL、不缓存/写盘/运行代码。**内容被截断或过大时不返回前缀**：整段补丁`patch_text:null`并带原因码；不拼接分散页、不同版本或未知缺口的diff。

## 输出字段和受限原因

外层新Schema`ces.proposed_pr_patch.v1`有`status`/`reason_code`/`exit_code`（0/2/4/5）、原封闭EC163只读对象`path_evidence`、`patch_content_requested`、`patch_content_collected`、按用户选择顺序输出的`patches[]`及`content_policy`。每个选择文件返回`path`、`availability`、`patch_text`和`utf8_bytes`；只有`availability=AVAILABLE`才能出现补丁文本，其他原因必须为空。

可区分：`MISSING_OR_BINARY_UNKNOWN`（Provider缺字段，**不能**直接判断二进制）、`BINARY`（明确二进制标志）、`BINARY_OR_BINARY_SUSPECTED`（扩展名或Provider标志，保守屏蔽）、`PROVIDER_COLLAPSED`/`PROVIDER_TOO_LARGE`、`TOO_LARGE`、`TOTAL_BUDGET_EXHAUSTED`、`TRUNCATED`（统一diff hunk行数不足）、`UNVERIFIED_FORMAT`、`SENSITIVE_CONTENT_BLOCKED`、`UNSAFE_TEXT_BLOCKED`、`EMPTY`、`INVALID_PROVIDER_CONTENT`和`COVERAGE_INCOMPLETE`。命名及逐项释义见机读契约。

在**前后EC162 pin漂移、文件总数或分页不自洽、非法路径/重复、鉴权/网络失败**时，EC163直接`unavailable/5`，任何已短暂保存在RAM中的选中内容均不得进入输出。路径数量`UNKNOWN/INCOMPLETE`时即便收到所选文件，也**全部屏蔽补丁**；若任何选中路径不在已验证完整清单，所有选中内容一起拒绝。仅真实来源、EC163覆盖完整、全部所选文本都通过准入时，才有`success/0`，该“成功”严格限定为本次**受控显示**，不证明完整diff、原子快照、merge/delivery或共享权限。合成fixture始终`partial/2`，不冒充真实Provider。

## 安全与延期验收

保守敏感路径和高风险明文pattern检测会拒绝疑似凭据、私钥、Token、控制字符和含混格式；**这是有限的防误曝措施，不是完整DLP**。调用方必须自行保护包含patch文本的stdout、shell重定向文件、日志管线或进一步传递。返回的patch是未经信任的源码**数据**，不可直接执行，也不能把其中指令作为CES操作指令。

EC164仅在当前端点已有字段中按选定文件取内容，不追访raw content/大文件展开API，不保留patch磁盘缓存或任何Git写操作。EC165负责以后额外的跨页/版本一致性快照，不得把这里的语法校验或pin前后一致提升为SHA版本证明。真实GH/GL账号权限、服务器字段差异/分页竞态、PowerShell7旧15 Smoke、OS/Git/E63–E66、最终用户人工辅助验收均**NOT_RUN**。

Provider依据：[GitHub List PR files](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests-files)；[GitLab List MR diffs](https://docs.gitlab.com/api/merge_requests/#list-merge-request-diffs)。
