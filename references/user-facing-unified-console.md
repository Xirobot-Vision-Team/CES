# EC278 — 用户可调用的 CES 统一操作入口（V5.88 / R278）

本轮只施工**一个功能**：将已经存在且固定注册的 EC241/243 Python Action Router 与原生 R150 PowerShell 两条入口组织成一个实际可执行的、权限不升级的操作者命令行。不是重写 Action Handler、授权提供者、Broker 或项目代码，也**不是**将旧的 11 个 `HOST_REQUIRED` 调度成有特权调用。

## 交付入口

- `scripts/ces_next.py`：Python 3 操作者入口，命令 `routes`、`describe`、`template`、`run`、`legacy`、`doctor`。
- `scripts/ces-next.ps1`：PowerShell 7 可选薄包装器；仅把原始参数数组交给隔离模式 `python -I -B scripts/ces_next.py`，不执行拼装的 PowerShell/系统 shell 字符串。
- 旧 `scripts/ces.ps1`、`scripts/ces_router.py`、`construction/unified_action_router.py`、EC243 `outcome_consistency.py` 等**字节不变**；原旧产品身份仍为 `V4.60/R150`，Router 仍为 `V5.53/R243`。**V5.88/R278 是新完整施工包标识，不代表原生 CLI 升版或联合质量通过。**

## 真实使用

在解压后的 `ces/` 根目录运行，Python ≥3.10（遵循已有 Handler 的运行要求）。建议所有现代调用使用 Python `-I` 隔离环境依赖：

```sh
# 读取真实 Router 中全部已注册的 74 条 Action/Mode；11 条仍需独立 Host
python3 -I scripts/ces_next.py routes --pretty
python3 -I scripts/ces_next.py routes --kind host
python3 -I scripts/ces_next.py routes --kind modern

# 查看固定 Handler、安全边界和该路由的未填参数骨架
python3 -I scripts/ces_next.py describe Due Evaluate --pretty
python3 -I scripts/ces_next.py template Due Evaluate --pretty

# 例：真实执行现有 EC191 Due/Evaluate (读日历决策，不调度，不发送)
cat > /tmp/ces-ec278-due-request.json <<'JSON'
{"schema":"ces.unified_action_router.request.v1","action":"Due","mode":"Evaluate","parameters":{"project_timezone":"UTC","cadence":"day","observed_at":"2026-10-24T12:00:00Z","never_processed":true}}
JSON
python3 -I scripts/ces_next.py run Due Evaluate --request-file /tmp/ces-ec278-due-request.json --pretty

# 环境诊断仅报告已观测的工具，不运行 15 Smoke 或最终质量验收
python3 -I scripts/ces_next.py doctor --pretty
```

上面的 `never_processed:true` 仅是**演示中明确给出的假定事实**，不是宿主验证真实调度状态。真实请求应由调用者按既有 Schema 提供当前且真实的参数。`template` 输出 intentionally 不带权限开关、外部 Token、网络凭据或虚构完整参数；生成后须人工补充真实 Handler 必需值才可执行。

安装并满足 PowerShell 7 的机器可使用：

```powershell
pwsh -NoProfile -File ./scripts/ces-next.ps1 routes --kind modern
pwsh -NoProfile -File ./scripts/ces-next.ps1 run Due Evaluate --request-file /path/to/request.json
```

原生旧功能由**旧脚本原样处理**，必须用 `legacy --` 与现代 JSON 调用明确分开：

```sh
python3 -I scripts/ces_next.py legacy -- -Action Inspect -RepoPath /my/repository -Json
python3 -I scripts/ces_next.py legacy -- -Action CodeShow -Mode List -RepoPath /my/repository -Json
```

如原生 PowerShell 未安装，回报结构化 `EC278_POWERSHELL7_NOT_INSTALLED`（退出码 5），**不会假装执行 Inspect/CodeSave**。需要持久化的旧 `CodeSave` 仍要求原脚本自己的 `-ApprovePersist`；新 launcher **不会自动附加**该许可。`legacy` 仅转发原始参数给确切的 `scripts/ces.ps1`，采用 subprocess argv 列表、`-NoProfile -NonInteractive -File`，没有 shell 插值和额外凭据。

## 安全与结果解释

1. `run` 先从现有 Router `--list-routes` 读取固定路由清单；旧 `LEGACY_NATIVE_R150` 与 `HOST_REQUIRED` 分别拒绝冒充现代调用。**11 个 HOST_REQUIRED 继续禁止无特权入口执行**。独立 Host 接入不由普通 JSON 控制。
2. `run` 用隔离 `sys.executable -I -B` 在独立进程调用原有 `scripts/ces_router.py`；不修改请求文件、不签署或臆造权限、不更换源项目或网络设置。原 Router 负责文件 `O_NOFOLLOW`/内容读取、Action/Mode 精确绑定、私有写操作 opt-in、网络 opt-in 及 Handler 调用；子进程 stdout 300KB 上限、超时、严格 JSON 和 exit/status 一致性核对；stderr 不会当成可信报告输出。
3. **现代 `run` 原封不动输出已标准化的 Router JSON**。实际 `partial / 2` 仅表示 Action 结果可观察，不能升级为 Quality PASS、成功完成、已授权、已认证操作者或已执行外部业务。
4. `routes/describe/template` 只是目录/样例，不是调用权限、当前服务可用性、产品完成度、Enterprise SSO 或 Provider 在线成功的证据。`doctor` 的 `pwsh` 是否存在不等于 PowerShell7 版本/Smoke 已验证。
5. 不复制原生 Handler 或修改 `unified_action_router.py` 权限闸门；不修改旧静态历史，尤其不允许新入口绕过 CodeSave、11 HOST_REQUIRED 或原 Router 的用途限定。

## 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 只读 `routes / describe / template / doctor` 观察成功；对 `legacy` 是原 CLI 自身的退出码，**不证明业务完成** |
| `2` | 现代 Router 返回保守 `partial`，未证明全局成功 |
| `3` | 缺失独立 Host/现代请求误用原生路由/未授权的本地写、网络读等拒绝 |
| `4` | 请求格式、Action/Mode、调用参数错误 |
| `5` | Router/Python/PowerShell 可执行环境、无效回执或资源不可用 |

## 本轮真实做过和未做过的核验

**已做：** Python 本地 12 个聚焦用例，含 74 条固定路由的目录、11 Host 拒绝、真实 `Due/Evaluate` 原 Handler 调用、现代写 opt-in 拒绝、原生和现代路径分离、PowerShell 不存在时拒绝、原生参数无 shell 透传 mock、异常回执拒绝、请求 Schema 拒绝、隔离模式不受 PYTHONPATH 注入影响。

**未做：** 当前 Linux 容器不提供 `pwsh`，因此**没有真实执行新的 `.ps1` 包装器或旧 PowerShell 15 Smoke**；Windows/macOS 参数边界、使用者仓库实际输入、真实专用 Host/Provider/凭据、外部联网、ESM 注册/企业策略、Podman+cgroup v2、完整 CES 联合验收仍需最后协助统一测试。本轮也未触发任何企业业务写入或生产数据读取。若需在部署中验证，请先在受控测试库运行上面的 `legacy` 命令，然后跑旧 15 Smoke 和已有 Router tests。

EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、最终验收 `NOT_STARTED` 全部维持；这是**功能代码交付，不是最终通过**。
