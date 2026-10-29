# EC248 — CodeShow Sequence 兼容与受限大图执行入口（独立可选）

**当前包 V5.58/R248；旧 PowerShell 本体仍 V4.60/R150，新 Router 仍 V5.53/R243。**
此次**没有替换旧 CodeShow**，没有对原 k1..56 算法的运算值做修正或扩阶。新增一个真实可执行的独立 Python POSIX 受限入口（不登记 Router Action）：[`construction/sequence_guard/guarded_sequence.py`](../construction/sequence_guard/guarded_sequence.py)。用户需要原生兼容时，仍可调用原 `pwsh -NoProfile -File scripts/ces.ps1 ...`；只有主动采用新入口才会受到新预算限制。

## 1. 实际可运行的受限功能

- 在启动 PowerShell 前，从 **EC244 冻结的 307 份源码指纹**中逐个比对当前 `ces.ps1` 与其 **124 处字面量点源的 124 个唯一模块**。`pathidentity.ps1` 是前置一处，其余 123 处为历史 EC154 计数范围；任何模块哈希/导入数量/k1..56 顺序或审计关键依赖漂移均拒绝启动。这是**同一工程内的完整性对账**，不是独立签名/可信授权。
- 只允许 `CodeShow/Sequence`、2～12 个不重复小写 ci-SHA256 ID、Top 1～20 以及原 CLI 对应的 11 种可选聚焦参数。Python 只严格预检安全且易辨认的编号/字符边界；其余互斥性和数据含义仍由**原有 CodeShow 处理器**验证。直接用数组调用 `pwsh -NoProfile -NonInteractive -File <冻结 ces.ps1> -Action CodeShow -Mode Sequence ... -Json`，不拼接 shell 字符串、不写仓库源码、不使用任何业务写开关。
- **默认墙钟 120 秒**；POSIX `RLIMIT_CPU` **120 CPU 秒/进程**、`RLIMIT_AS` **8192 MiB/进程虚拟地址空间上限**；stdout+stderr **总量 8 MiB**。增量读取两路 pipe，进程组超时/输出过量时杀停并丢弃部分输出，不用无上限的 `communicate()` 或临时文件积累。预算有上下界，均可通过命令行缩小/放大，**不能关掉硬限制**。
- 只在原生返回一个可解析 `ces.cli.v1` / `CodeShow` JSON、其 `status` 与 `0/2/3/4/5` 退出码相符的情况下原样写出原 JSON 字节；不把原生 `partial/2`、`invalid_input/4`、`unavailable/5` 说成 `success`。受限入口自己的错误用 `ces.ec248.guarded_sequence.error.v1`，不拼出部分源码、完整参数或路径；退出码为 4（输入/预算）或 5（执行/限制错误），不会被误读为原 Native JSON 业务成功。
- 没有 `pwsh` / 缺 POSIX 资源硬上限时直接拒绝 native 执行；`--plan` 仍能只读列出加载风险。**Windows 上新受限入口不是已实现的 OS Job Object 资源隔离**，当前明确拒绝，而不退化成无硬限额的运行。

## 2. 最短命令

```sh
# 只读：不需要 pwsh、不连接业务 repo；显示真实文件总量、56阶、19条父重算与懒加载风险
python3 -I -B construction/sequence_guard/guarded_sequence.py --plan

# 示例：使用**实际保存过的**两个不同 ci-SHA256 ID，指定真实绝对仓库路径
python3 -I -B construction/sequence_guard/guarded_sequence.py \
  --repo-path /absolute/path/to/existing/repo \
  --record-ids "ci-<64位小写hex>,ci-<另一条64位小写hex>" \
  --top 10 --timeout-seconds 180 --cpu-seconds 180 \
  --virtual-memory-mib 8192 --output-mib 8

# 深层第5级聚焦：原生参数一一保留，不增加新k字段
python3 -I -B construction/sequence_guard/guarded_sequence.py \
  --repo-path /absolute/path/to/existing/repo --record-ids "<真实ID1>,<真实ID2>" \
  --sequence-pair-overview-index 1 --sequence-pair-path-index 1 \
  --sequence-pair-path-anchor-index 1 \
  --sequence-pair-path-anchor-finding-side left \
  --sequence-pair-path-anchor-finding-index 1 \
  --sequence-pair-path-anchor-finding-counterpart-index 1
```

`--record-ids` 示例尖括号为**说明性占位**，不能直接当作合法 ID 运行；应使用真实的两个不同完整小写 `ci-` 记录。新入口只能在安装了 PowerShell 7 且 POSIX `resource` 支持 `RLIMIT_CPU` 和 `RLIMIT_AS` 的环境运行；本环境没有 pwsh，因此**没有运行原生 CodeShow 或 E63–E66**。

## 3. 懒加载评估——明确选择暂不改写

EC154 统计 `ces.ps1` 后半段 123 个点源，EC248 同时核查了前置 `pathidentity.ps1` 一处，因此完整启动的 **124 个 PowerShell 模块、共约 7,287,960 字节（含主 CLI）**。`CodeShow/Sequence` 有 56 个已承诺的 k 输出，k38～k56 源中存在 19 条连续显式父级重算和完整父 JSON 对照。对这一路径**仅删掉看似未使用的 dot-source 模块**，无法证明没有全局函数名、初始化变量、动态引用/共享 helper 依赖，也无法证明 E63–E66 结果兼容。

因此 EC248 对懒加载的决定是：**`ASSESS_ONLY_NOT_ENABLED`**，不改变 124 处原生导入顺序，不声称启动速度改善；下一阶段若考虑真实实现，先在用户环境建立 PowerShell AST 与函数间/点源顺序调用图，记录原生基线 JSON（含不存在字段 vs `null`、index 互斥规则、全部 k1..56 counts），再对不同聚焦路径和 E63–E66 在**同输入、不同隔离进程**实测 wall/CPU/峰值 RSS/虚拟内存/输出和一致性。**E63–E66 均未进行真实基准实验，未证明存在算法故障或已经加速。**

## 4. 兼容和资源保护的真实边界

| 场景 | 结果 | 界限 |
|---|---|---|
| 原 `scripts/ces.ps1` 所有 CodeShow 模式 | 原样保持 | 未被新 guard 替换，旧调用仍无此预算限制 |
| 新 guard 的 Sequence 无错误结束 | 传回**原生** JSON 与原生 0/2/3/4/5 | 不生成新的 k 语义或 JSON 主字段；原生未在本环境运行 |
| 新 guard 预算触发 | 终止 POSIX 进程组、返回独立 Guard 错误，无部分 JSON | 部分独立脱离进程组/同 UID 恶意进程/子进程总内存不是已证明隔离 |
| Linux/macOS POSIX 本地进程 | `RLIMIT_AS` 虚拟地址上限、CPU per-process、墙钟和 pipe 限额 | CPU/虚拟内存是**单个进程**上限；`RLIMIT_AS` 可能使正常 .NET 进程初始化提前失败 |
| Windows 原生系统 | 新受限入口拒绝而不放松 CPU/AS 限制 | 原 CLI 仍可用；Windows Job Objects/独立沙箱有待工程实现与用户验收 |
| PWSH、git、权限/凭据 | 新入口不创建凭据、不授权访问、不独立提供 OS 沙箱 | 环境变量和 Git 配置继承原进程；真实授权/安全审计并未证明 |

## 5. 本轮本地验证与待用户集中验证

```sh
python3 -I -B construction/sequence_guard/test_guarded_sequence.py
python3 -I -B construction/sequence_guard/guarded_sequence.py --plan
```

16 个窄范围专项本地用例已执行，包括真实 Python 子进程的墙钟超时与 **>1MiB** 输出拒绝、原生 JSON/status 形状、11 个参数转发、冻结源 SHA、输入边界、缺 pwsh 拒绝及不泄露源路径。**这些是受限执行机制的本地开发测试，不是一个真实 PowerShell7 CodeShow 回归，也不能说明 CodeShow 的 E63–E66 计算性能或受限环境完整安全。**

最终用户统一验收应在合法真实 Git 测试工作区和可用 PowerShell7 上，先运行原来的 `tests/CodeShow.Smoke.ps1`、`tests/CodeSequence.Smoke.ps1`（再及原 15 Smoke）；比较 guard 与旧 `ces.ps1` 在**同一原生请求**的 status/退出码/公开 JSON，分别重复普通和深层聚焦、错误索引、无匹配路径、2/12 ID 上限以及 E63–E66 性能样例。先确认 PowerShell/.NET 在当前 OS 上可启动并具备合适内存预算，不能把故意限额终止作为原函数错误。最后再测试 Windows/macOS/Linux、多进程、权限、特殊路径/环境、文件变化、子进程泄漏和进程组终止。原旧 CLI/15 Smoke/R150 k1..56 和 EC242/243/244 原资源未经字节改动；B001 **OPEN**。
