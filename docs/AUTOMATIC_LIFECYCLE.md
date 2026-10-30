# 分析前同步与仅构建、文档自动发布

入口：ces-product.cmd lifecycle preflight|pull|build|publish|status。仓库目标、分支、工具链、构建参数和授权范围来自外部profile；CES实现不内置样本项目。

## 每次分析前
repository_sync.enabled/allow_pull和execution_policy.build_before_analysis明确开启后，prepare与周/月/年报告入口先执行preflight。可单独使用 lifecycle preflight --config <profile> --execute。
先fetch当前配置origin分支；仅在本地HEAD为远端祖先时ff-only前进，不rebase、stash、reset或clean。已有暂存区改动、分叉、远端变更与本地编辑冲突会停止；所有原有本地编辑内容哈希核对保留。
构建只使用build_validation.steps中kind=build的argv/cwd/timeout。run_runtime_tests必须明确false；不启动业务程序、不运行测试或设备。构建目标即使名为Test也只是生成其二进制，不执行它。
命令、HEAD、配置、退出码、日志哈希、耗时和源码稳定性写入外部lifecycle缓存。业务源码有未提交修改时先保护现场并报告受阻，不声称验证了远端提交。构建失败可以继续独立代码分析并报告原因，不能改业务逻辑凑通过。
增量编译保留当前项目的正常Build语义；不自动Clean/Rebuild、不升级工具链、不为了CES修改项目工程。VS中曾构建成功与本轮退出结果独立记录。
周期总结先运行不带--analysis的入口完成同步/构建并生成绑定输入，Codex据此撰写综合评述；带--analysis完成同一轮发布时复用该回执，不重复构建来改变输入绑定。完成前复核本地/远端HEAD、源码、构建命令和日志哈希；回执超过24小时或证据变化就停止，需开启新一轮分析。

## 构建成功与修复验证
Build成功只证明所配置目标生成成功，不证明算法效果、运行行为、单元测试或Issue已修复。明确禁止runtime tests的profile拒绝track test执行；原有fixed/regression验收门不被弱化。静态源码可记not_fixed/inconclusive，缺少必需运行证据时不自动关闭。

## 文档生成后自动发布
可选README维护默认开启，随knowledge prepare/publish触发。除成品目录外，独立索引仅可增加readme-manifest.json精确登记、且父提交人工区未改的README路径；仍拒绝业务代码或其他根目录文件。README草稿须绑定实际来源和本批知识，不能把复制链接当功能分析。详见[README维护](README_MAINTENANCE.md)。
用户已有长期明确授权、repository_push.allow与automatic_after_document_write开启时，knowledge publish --execute和documents --execute生成后调用autocommit。可单独 lifecycle publish --config <profile> [--execute]。
提交范围限定repository_docs.relative_directory内托管manifest列出的文件和manifest本身；成员外部编辑、无关未托管文档或缺失文件冲突停止，不覆盖、不删除成员内容。
只读远端HEAD必须与本地HEAD一致；若生成期间远端前进，停止发布、下轮重新同步和复核。使用独立Git索引从当前HEAD写树，逐项核对差异只含文档，再commit-tree生成正常子提交并正常push。绝不force。
文档提交附带CES-Generated-By与CES-Repository-Id机器trailer；回读远端后保存lifecycle/publications/<commit>.json逐提交回执。启用审计排除时核对这些来源及manifest路径，避免日周月年把CES输出当成新增工作。成员正常文档或混合业务提交仍保留。
远端确认后，仅在本地分支/索引/工作区仍为原状态时前移分支并原子更新Git索引，保留其他未暂存编辑。已有暂存改动则阻止发布。构建产物、日志、缓存、凭据和业务源代码不会混入文档提交。
last-publish记录commit_prepared、pushed_remote_verified或published_and_local_branch_synchronized。推送不确定时先ls-remote/对账；不重复造提交，不用reset/强推掩盖竞争。远端已确认但本地同步受阻时明确报告。

## 配置
    repository_sync: enabled / allow_pull / remote / branch / strategy=ff_only
    execution_policy: build_before_analysis=true / run_runtime_tests=false / launch_application=false
    build_validation: enabled / configuration / platform / steps[{name,kind=build,argv,cwd,timeout_seconds}]
    repository_docs: relative_directory / allow_write / allow_git_commit / allow_git_push
    repository_push: allow / automatic_after_document_write / commit_message

命令中可用{repository}、{build_log}、{cache}占位符。默认模板所有拉取/执行/提交推送开关关闭；配置不能代替人类授权。真实环境的Release/x64等参数只存在profile，不加入通用源代码。

## 自动化
已获持续授权的Codex日报与周期任务可使用该流程：分析前同步和实际构建；不运行测试；知识文档增量完成后只推送托管成品。具体任务、执行时间和GitHub提醒方式以外部配置为准。
Codex仍负责实际分析、知识章节推理和周期综合评述；Python不复制旧草稿来冒充新分析。

