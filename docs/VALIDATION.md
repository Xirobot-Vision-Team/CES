# CES 1.0 基准验证

验证时间：2026-10-27 13:07 UTC+08:00。状态：本地基准，保留已知限制。

- Linux / WSL：Python 3.12.3，15 个模块共 444 个用例全部通过，无跳过。包含 13 组主要功能，以及路由与结果契约回归。
- Windows：Python 3.12.10、PowerShell 7.6.9、Git 2.55.0。响应契约 15/15，路由注册 10/10；静态源码契约 MATCH。
- Windows 原生 Smoke：15 套已执行，14 通过，1 套 Sequence 深层用例失败，0 未运行。七类 Action 基础能力通过。
- 两个入口均显示 1.0.0，路由清单 74 条。无独立 Host 的请求仍被拒绝，未增加权限。
- 1.0 的响应源码锁、原生源码基准和完整文件清单按当前字节建立；整理前包另存恢复备份。

| Python 模块 | 测试数 | 结果 |
| --- | ---: | --- |
| test_ai_handoff_router | 28 | PASS |
| test_codeprepare_multisource | 31 | PASS |
| test_cycle_next | 32 | PASS |
| test_cycle_summary | 42 | PASS |
| test_delivery_preview | 20 | PASS |
| test_finding_save | 31 | PASS |
| test_issue_match | 32 | PASS |
| test_knowledge_bootstrap | 24 | PASS |
| test_proposed_pr_snapshot | 33 | PASS |
| test_quality_detect | 40 | PASS |
| test_quality_read_ci | 40 | PASS |
| test_report_render | 28 | PASS |
| test_response_contract | 15 | PASS |
| test_unified_action_router | 22 | PASS |
| outcome-consistency-v1 | 26 | PASS |

| Windows Smoke | 结果 | 秒 |
| --- | --- | ---: |
| Inspect | PASS | 30.64 |
| Collect | PASS | 16.53 |
| DeliveredTarget | PASS | 49.0 |
| Reconcile | PASS | 78.17 |
| CodePrepare | PASS | 110.11 |
| CodeValidate | PASS | 116.42 |
| CodeSave | PASS | 144.61 |
| CodeShow | PASS | 161.08 |
| CodeFindings | PASS | 280.44 |
| CodeCompare | PASS | 133.86 |
| CodeTrace | PASS | 260.33 |
| CodeOverview | PASS | 252.26 |
| CodeTriage | PASS | 254.59 |
| CodeRecurrence | PASS | 239.51 |
| CodeSequence | FAIL | 150.2 |

用例使用合成证据及独立临时 Git/私有存储，不代表外部业务集成。没有接触真实项目、远端 Issue/CI/Provider 或真实密钥。Sequence 及其他未验收能力见 KNOWN_ISSUES.md。
协议 schema、哈希域、错误码与内部包导入标识保留兼容；产品版本、根文档和当前源码元数据使用 1.0。历史审计兼容工具不作为本基准的当前完整性入口。
