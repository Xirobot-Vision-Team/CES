# 使用入口与旧协议

新安装先读[INSTALLATION.md](INSTALLATION.md)。当前产品流程见
[PRODUCT_GUIDE.md](PRODUCT_GUIDE.md)，完整命令列表使用
`python -B operator/ces_product.py --help`。

## 原生证据接口

PowerShell 7 和 Git 必须已安装。显式传入待分析仓库的绝对路径，不以 CES
源码目录代替项目目录。Inspect、Collect 等默认只读；读取 diff、未跟踪内容
和保存 CES 状态分别有独立参数。

```powershell
./ces.cmd -Action Inspect -RepoPath '/absolute/path/to/project' -Json
./ces.cmd -Action Collect -Mode WorkingTree -RepoPath '/absolute/path/to/project' -Json
./ces.cmd -Action CodeShow -Mode List -RepoPath '/absolute/path/to/project' -Json
```

CodePrepare/CodeValidate/CodeSave 使用 Snapshot 和 EvidencePath，校验/保存另需
绑定草稿 InputPath。CodeSave 需明确 ApprovePersist，只写 CES 状态而非业务源码。
详见 scripts/ces.ps1 的帮助及隔离 tests/ 示例。

## 历史 POSIX 扩展

旧宿主协议要求的私有权限、签名/审批、主机隔离边界均保留。安装不替代这些条件，
请求仍可能因 Host 未配置而拒绝。WSL 安装及可选发行版/运行目录设置见安装文档。

`PRODUCT_SHA256.json` 校验当前发行物，另外核对 protected legacy 文件。
`BASELINE_SHA256.json` 与 verify_baseline.py 是原 1.0 历史整包比较；当前新增
文件和更新文档使其不再适合作为当前产品的通过入口。不得改写历史清单掩盖差异。

历史测试摘要仍在 [VALIDATION.md](VALIDATION.md)，不是本次重新运行全部旧测试
的证明。公开源码不包含原部署带个人目录的 validation.json；省略项在发行记录披露。
