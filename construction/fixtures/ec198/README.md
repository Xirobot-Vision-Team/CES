# EC198 本机合成用例与无真实凭据说明

`construction/test_report_writing_handoff.py` 在内存里调用真实 EC192→193→194→195→196→197 的上游函数，构造**两仓库虚拟 report scope 与独立收据 SHA 字符串**，再调用 EC198 `ReportWritingHandoff.bind/from_json`。虚拟 SHA 仅用于门禁行为覆盖，不是已签署的人工授权或外传许可。不会生成包含真人邮箱、真实日志、Git 对象、个人绩效或发布结果的持久化 fixture。

覆盖独立的固定-purpose `report_writing` 审核授权、逐仓收据不复用、scope/metrics/period/source/people 精确绑定、每仓 `cesrc1` 完整 citation 集合、显式四渠道未知/撤留/局部/ProposedPR 状态，反例包含伪造 AI pass、跨仓引用、恶意多字段注入、篡改 EC197 原始规范字节、篡改输出与更改审核授权后的从原件重算拒绝。

在具备 Python3 和 `jsonschema` 的环境中，从 `ces/construction` 执行 `python -m unittest -q test_report_writing_handoff`。这仅是开发环境的合成逻辑检查，**没有**做真实 EC171 live Handoff、EC174 callback、外部 AI 请求、native PowerShell7 或原始15 Smoke、真实 Git/CI/provider、凭据签名真实性、隐私审批、跨平台/E63-E66/最终验收。更多用法见 [`references/report-writing-handoff.md`](../../../references/report-writing-handoff.md)。
