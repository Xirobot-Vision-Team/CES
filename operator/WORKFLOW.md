# CES 当前操作工作流

此文件是通用产品操作指南；配置、证据和成员数据都在仓库profile或产物中，不能写成CES专用规则。

1. doctor读取外部profile与已有授权。启用分析生命周期的profile先fetch/ff-only同步并按配置实际Build，不运行程序或测试；prepare与周期报告入口已内置，参见../docs/AUTOMATIC_LIFECYCLE.md。
   启用Issue追踪的profile先执行track sync；即使没有新代码也检查问题处理进展。需要时track prepare/review及实际配置测试，报告保存闭环状态；关闭/重开保持独立权限与证据门。见../docs/ISSUE_TRACKING.md。
2. prepare采集实际工作区或显式提交范围；Codex阅读review packet和必要上下文，完成深度代码分析。
3. complete重新CodeValidate；issue使用完整source-bound深度分析去重创建问题/建议。
4. report daily按实际作者归档日报；notify把代码问题和日报归属为账号可见待办。
5. 周/月/年先复用下级报告。完整skill快捷指令还要由Codex对遗漏、风险和重要变更补充代码分析并保留独立证据，不重复审阅全库。月同时查阅日报/周报，年同时查阅周报/月报，随后按授权发布报告并通知维护人。
6. knowledge prepare查看显式源码来源及变化。Codex只复核受影响知识章节，引用真实提交、行和必要引文；knowledge publish生成仓库知识成品。
7. documents把可读报告与README索引写入仓库docs/ces。用户编辑冲突则停止，已有长期自动发布授权且profile开启时，仅自动提交推送托管文档。其他profile仍默认关闭。

注意：缓存可读成品、GitHub报告Issue、作者待办、站内通知与邮箱投递分开验收。用户当前接受GitHub账号提醒；不要求绕过个人通知设置发送邮件。

配置模板：operator/profile.example.json。模板全为占位值且写操作默认关闭。

没有用户明确要求就不建定时器。手动与已有授权定时任务均可使用本流程；实际启用状态以外部profile与Codex自动化配置为准。实际推理由Codex完成而非Python凭空生成结论。

自然语言快捷指令：仓库每日分析、仓库周总结、仓库月总结、仓库年报告。具体流程见../docs/REPOSITORY_SHORTCUTS.md；当日任务包括实际配置的构建测试和失败问题分析。未配置的步骤不能声称已执行。

验证：python -B tools/verify_product.py。旧verify_baseline.py仍用于比较旧1.0完整包，而非当前产品扩展。


当前profile禁止track test执行；Build通过不等于运行测试、算法正确性或Issue修复验证通过。

手动扩大覆盖使用“仓库知识扩展”，按references/knowledge-expansion.md逐批补齐、维护coverage.md与续接点；它不加入定时任务。knowledge prepare支持--sources-file覆盖本轮来源，不改profile默认列表。
