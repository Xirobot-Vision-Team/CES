# EC165 离线开发fixture范围

由 `construction/test_proposed_pr_snapshot.py` 生成与组合 `ec161/`、`ec163/`、`ec164/` **已有纯合成**GH/GL元数据和变更文件，再叠加模拟的HTTP ETag、Last-Modified、raw-body 摘要及分页终止信号。

开发时覆盖：完整/未知/封顶路径覆盖、有序单页/双页、ETag强弱与缺失、双次GET页/内容与pin漂移、无授权补丁默认不披露、选中明文hash、`git ls-tree`本地孤立仓头提交blob关系、收据离线重算及篡改拒绝。**没有任何线上访问、真实Token、真实PR或PowerShell CLI运行。**

运行 `python construction/test_proposed_pr_snapshot.py -q`。
