# CES Engineering Suite

简体中文 · [English](README.en.md)

CES 将仓库报告、代码问题、知识文档和可选测试审查串成可追溯的工程工作流。
助手阅读真实源码并撰写分析，CES 负责采集、绑定、校验、归档及经授权的发布；
格式化报告、退出码 0 或 Build 成功不会被当作缺陷根因或修复已经证明。

## 能做什么

- 日报及周/月/年总结，保留来源、作者/committer、覆盖范围和缺口。
- 代码问题与优化建议的证据校验、归属、去重、GitHub Issue 及持续追踪。
- 来源绑定的知识章节和报告增量维护，仅发布 manifest 托管文档。
- 用户指定测试入口后的协议登记、结果采集、分析和测试报告 Issue。
- 函数/功能开发者登记：问题用例匹配开发者，自动抄送报告。
- GitHub @提及、Assignee 和项目级抄送，保留发送账本和回读证据。

所有项目路径、命令、成员和接收人来自外部 profile；运行测试、推送、发布与调度
默认关闭。CES 不内置项目专属行为，也不保证 GitHub 原生通知邮件实际入箱。

## 快速开始

需要 Python 3.12+、Git；原生源码采集另外需要 PowerShell 7。

```powershell
py -3.12 -m venv .venv
& ./.venv/Scripts/python.exe -B operator/ces_product.py --help
& ./.venv/Scripts/python.exe -B -m unittest discover -s operator -p 'test_*.py'
& ./.venv/Scripts/python.exe -B tools/release_check.py
```

Linux 使用 `python3 -m venv .venv` 和 `.venv/bin/python`，也可 `sh ./ces-product --help`。
测试仅使用隔离夹具和模拟服务，不需要 GitHub 凭据。可选兼容模块的依赖见
[安装说明](docs/INSTALLATION.md)，不要把虚拟环境一起上传。

将 `operator/profile.example.json` 复制到源码树之外，填写项目路径及账号身份，
先保持执行/写入开关关闭。通过 `doctor --config <profile>` 检查范围。
Windows 的 `ces-product.cmd` 与直接调用 `operator/ces_product.py` 使用同一操作层。

配合 CES skill 可调用“仓库每日分析”“仓库周总结”“仓库月总结”“仓库年报告”、
“仓库知识扩展”和“仓库测试审查”。这些短语是助手编排入口，安装本身不建立定时器。

## 文档

- [安装与支持范围](docs/INSTALLATION.md) · [架构](docs/ARCHITECTURE.md)
- [产品指南](docs/PRODUCT_GUIDE.md) · [仓库快捷流程](docs/REPOSITORY_SHORTCUTS.md)
- [测试审查与开发者登记](docs/TESTING.md) · [通知与验收](docs/NOTIFICATIONS.md)
- [Issue 追踪](docs/ISSUE_TRACKING.md) · [同步与文档发布](docs/AUTOMATIC_LIFECYCLE.md)
- [贡献说明](CONTRIBUTING.md) · [开发验证](docs/DEVELOPMENT.md)
- [安全政策](SECURITY.md) · [信任边界](docs/SECURITY_MODEL.md)
- [已知限制](docs/KNOWN_ISSUES.md) · [开源发布清单](docs/OPEN_SOURCE_RELEASE.md)

当前操作层版本在 `PRODUCT.json`；根 `VERSION` 保留 1.0 兼容协议语义。
旧实现目录因导入路径和协议绑定保留，存在不表示所有旧路由已经生产验收。
原生 Sequence 深层查询的历史失败仍明确记录，没有从支持范围中隐去。

本项目采用 **Apache-2.0**。参见 [LICENSE](LICENSE)、[NOTICE](NOTICE) 和
[第三方依赖说明](THIRD_PARTY.md)。源码完整性与本地测试结果不等于独立安全认证。

Release preparation: **1.8.0**. See [cleanup and release scope](docs/CLEANUP.md).

Use the existing `$ces` skill for **CES 项目维护** to maintain the selected CES GitHub source repository. See [maintenance mode](docs/MAINTENANCE.md); no separate skill or scheduler is installed.
