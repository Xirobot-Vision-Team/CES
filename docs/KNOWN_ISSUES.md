# 功能边界与已知问题

1. Windows 原生七类 Action 的基础测试已通过。CodeShow 的 List、Detail、Findings、Compare、Trace、Overview、Triage、Recurrence 可按已测输入使用；Sequence 深层查询存在 Count 属性错误，暂不纳入支持模式。
2. AI Handoff、Finding 私有保存、QualityDetect、Report 安全保存、Knowledge、Delivery、Cycle 等 POSIX Python 流程应使用 Linux 文件系统中的私有存储。WSL 结果不代表 Windows 原生 Python 同样可用。
3. QualityDetect 依赖目录元数据和所选路径的有范围检查，同一时间戳刻度内的变化可能不可区分；它不提供原子目录快照。
4. 74 条注册路由是接口清单，不表示所有外部业务已接入。Host/Provider 默认拒绝，凭据、审批和业务集成须另外配置。
5. 历史签名审计模块、schema 名、哈希域与模块名中保留兼容标识；没有据此证明真实外部来源、完整历史链或生产验收。
6. 失效施工计划/进度/完成度快照及其一次性检查器已在1.8.0移除；历史可从Git查看。仍被实际运行检查使用的路由、源码绑定及安全元数据保留；不因清理而放宽运行授权。
7. 当前产品完整性入口是 tools/verify_product.py，PRODUCT.json 标记操作层1.8.0。VERSION、baseline.json、BASELINE_SHA256.json及verify_baseline.py保留原1.0协议/包快照语义，不能据此判断操作层缺失，也不改写原历史校验值。
8. 仓库每日分析、仓库周总结、仓库月总结、仓库年报告是Codex编排的skill快捷指令；Python不自行生成新AI结论。构建命令缺失时明确记录待配置，不能宣称已运行。上级报告先复用归档，再按需要补充有范围的代码审阅。
9. 新的仓库知识文档入口具有来源引用与托管哈希检查，但不能证明知识语义正确或自动覆盖全库。有明确持续授权且profile开启时，文档写入后自动提交推送托管成品；默认配置关闭。定时器仍需独立授权。
10. Issue追踪已接入操作层及定时任务。仅构建不满足运行行为修复验收；禁用runtime tests或缺少必需测试证据时，不能只据Build成功标fixed。自动关闭/重开默认独立关闭。状态机测试不代表真实生产环境关闭/重开已验收。
11. 独立项目测试默认关闭，结果协议须由实际入口/写报告源码审阅登记；支持六种通用协议，未知协议、缺失报告、计数不一致或全跳过不会记通过。二进制哈希不独立证明与源码构建对应，本机未签名回执不是防恶意测试进程篡改的沙箱。项目测试报告和track修复门分开，详见TESTING.md。
