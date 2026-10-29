# CES目录与版本说明

| 位置 | 职责 |
| --- | --- |
| operator/ | 三大功能的权威操作实现；不含实际仓库profile或凭据 |
| scripts/、construction/、references/ | 1.0兼容实现、协议及测试资源；导入路径保留 |
| docs/PRODUCT_GUIDE.md | 当前产品流程和参数指引 |
| docs/REPOSITORY_SHORTCUTS.md | 四个报告快捷指令及手动知识扩展路由 |
| references/knowledge-expansion.md | 分批扩大知识覆盖、预算与接续进度 |
| docs/NOTIFICATIONS.md | GitHub原生指派、提及及收件确认边界 |
| docs/VALIDATION.md、BASELINE.md | 1.0历史验收与整理快照，不是当前全功能通过证明 |
| tools/verify_product.py、PRODUCT_SHA256.json | 当前产品文件一致性与旧协议实现独立比较 |
| tools/verify_baseline.py、BASELINE_SHA256.json | 原1.0整包历史字节比较 |
| SKILL.md、agents/ | 可安装技能入口与界面元数据 |
| operator/profile.example.json | 安全默认关闭的通用配置模板 |

安装目录与项目数据目录由部署者选择；profile、缓存和账本必须位于独立外部数据目录。旧路径可通过显式profile保留，不以开发者本机布局作为默认值。

知识、技术文档、周期报告和代码分析成品位于目标仓库配置的docs/ces目录，缓存及发送账本不得入库。Git推送需要明确授权；持续授权并开启自动发布后，文档写入会自动提交推送托管成品。

PRODUCT.json中的operator_version为1.8.0，core_protocol_version为1.0.0。VERSION与baseline.json保持原协议语义；不要为了展示版本同步改动历史协议或哈希域。

安全整理仅归档已确认不再使用的重复运行文件和临时索引。没有清空发送账本、知识版本、实际profile、原1.0清单或已知失败记录。

快捷指令及辅助文档随技能包和产品包共同维护。当前操作指南以docs/REPOSITORY_SHORTCUTS.md为权威；references同名文件保留历史协议字节和原部署路径，不覆盖其校验域以追求文档文本相同。

SMTP试装代码已归档，当前产品不提供独立发件或邮箱映射。实际通知测试确认在仓库外数据目录保存，不能包含在通用安装包中。


公开源码包含Apache-2.0许可、贡献及安全说明、CI和独立发布检查。历史协议参考文档保留原字节；当前操作指南以docs/为权威，不要求修改历史引用同步元数据。
