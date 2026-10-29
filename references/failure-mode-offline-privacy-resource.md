# EC245 — 断网、保密、资源限额：失败策略与最终验证交接

> 工程包 V5.55/R245，2026-10-24。**本地合成故障用例**不是线上/企业/原生/OS 证据；仅一轮 EC245，不创建 EC246 业务路由。

## 真实实现范围

新增 **只读、可复现的 26 个负向测试场景**，运行既有处理器的真正输入边界、返回码和保守失败路径，不经网络、不会接管宿主凭据/授权，也不做业务库写入。

- [运行器](../construction/negative_scenarios/run.py)：**独立的开发用场景执行器**，不是 CES 统一业务路由或业务权限网关。`-I -B` Python 在本文件内部只添加固定的 CES `construction/` 路径，依靠 `unittest.mock` 将 socket 连接与 Python 子进程启动设为失败，网络场景仅使用内存 transport/opener。**这不是 OS 沙箱**：无法证明第三方扩展、原生子进程、非 Python 网络通道或所有本地副作用不存在。
- [场景 fixture](../construction/fixtures/negative_scenarios/scenarios.json)：每个场景固定 `id/family/boundary/fault/expected/needs_external`，合成用例预期退出码只可能是 `2/3/4/5`。不包含真实凭据、人员数据或真实私人仓路径。所有期望都需要实际本地 handler 的状态与 reason 精确匹配，禁止自动把 `success` 当作通过的业务事实。
- [本地场景结果快照](../construction/EC245_LOCAL_REPORT.json)：26 条仅限合成环境的固定状态及验收标记，没有原始处理器私密对象。
- [专项本地测试](../construction/negative_scenarios/test_cases.py)：fixture 参数失真、重复 JSON key、超大 fixture、符号链接、不允许的状态和未知用例全部保守拒绝；同时执行了实际既有 Router、Provider、CI Reader、Delivery Preview、Redaction、Report Render 的负面路径。
- 新工具位于 `construction/negative_scenarios/` **子目录**。它是单独启动的开发测试入口，**不由统一 Router 授权**；EC244 先前 142 个**顶层**直接主入口、74 条 Router 路由、41 门禁与 307 个历史源码 SHA 锁均**未改写**。不得把 EC244 旧时点的完整性清单解释为已覆盖新增 EC245 文件。

## 运行与结果（不触发线上验证）

从工程根目录 `ces/`：

```sh
python -I -B construction/negative_scenarios/run.py --list
python -I -B construction/negative_scenarios/run.py --run
python -I -B construction/negative_scenarios/run.py --case NET-01 --case PRV-05
python -I -B -m unittest discover -s construction/negative_scenarios -p 'test_*.py' -v
```

只输出 1 个 JSON 对象（没有原始 HTTP body、异常字符串、密钥、完整输入或原始业务结果）：

- `LOCAL_SIMULATION_PASSED_NOT_ONLINE_ACCEPTANCE`：本地模拟判定**全数**符合固定结果，退出 `0`；仅仅是开发场景通过。
- `LOCAL_FIXTURE_FAILURE`：任一场景的原始代码结果与期望不符、泄漏合成 canary、含伪权限/写入成功，退出 `2`。只输出固定的状态和原因，不把原始异常写入输出。
- `INVALID_LOCAL_FIXTURE_OR_REQUEST`：fixture 非有界普通文件、重复键、状态/退出码/案例集失配、意外 case ID 等，退出 `4`。不执行场景。
- 每条 `real_provider_or_host_verified=false`，整表 `scenario_level=LOCAL_SYNTHETIC_ONLY`、`final_user_assisted_acceptance=NOT_RUN`。`CON-02` 的正向模拟 CI 响应**仍然是 partial、SYNTHETIC、NOT_PROVEN_SYNTHETIC**，不声称有真实 CI。

### 固定场景覆盖（共 26 个）

| 类别 | 场景 | 既有处理器真实覆盖 | 对模拟/现场证据的限定 |
|---|---|---|---|
| Offline 6 | `NET-01`…`NET-06` | Router 网络独立 opt-in、EC161 默认断网/Transport 抛错/HTTPS 重定向、EC182 独立授权最终撤销与全局 network off | `allow_network` 不等于组织授权；注入 HTTP 失败不代表真实线路已断 |
| Privacy 11 | `PRV-01`…`PRV-11` | HostOnly DeliverySend、CodeSave opt-in、拒绝额外 credential 字段；不可信 CLI 输出 duplicate key、API 私密异常；CI exception secret 抑制；DeliveryPreview 门禁；DeliveryRedaction 对 token/path/Unicode bidi/email 的真实识别 | 合成 canary 只是特定测试字符串；不证明可阻止**所有**私人文本泄漏 |
| Resource 7 | `RES-01`…`RES-07` | CLI 参数上限、45s 超时模拟、262KiB 结果上限；EC161 1MiB JSON 响应；EC182 3 页上限；EC221 8 个来源上限；EC199 报表手交输入限额 | 模拟超时不等于真实 OS 终止保证，临时 stdout 文件*写入期间*未有硬性配额 |
| Consistency 2 | `CON-01`…`CON-02` | 子处理器自报 success 只变成 V2 partial；模拟 GH CI 200/成功 job 只是元数据，不是 CES 执行和人工授权 | 不构成 actor/source/Git SHA/CI 真实签证 |

**资源层真实限制与剩余风险：** EC243 Router 读回输出后才拒绝 `MAX_RESULT`，其临时 stdout 文件可能在 45 秒之内增长超过限额；直接导入 API 的最大时长/内存也不能由此运行器限制。EC248 专门处理 CodeShow 大图/性能风险；本轮不冒充完成 OS cgroup、进程树回收、磁盘配额或 E63–E66。CI 读取器的模拟统计是合成计数而非真实联网字节。

## 发生故障时的保守处理策略

1. **断网、TLS/HTTP/Provider 不可用：** 停止此次外部证据升级，标明 `offline`（若原处理器专用状态）或 `unavailable`；不能因凭据/网络 opt-in 自动重试、写入、发布、修改已有 Issue、补造 Git 合并/CI 完成。不同模块保留原固定 reason code；统一 Router 仍按 EC243 五态收敛，不改 74 个处理器分发。
2. **凭据/身份/读权限不足或中途被撤回：** 出口不给原始 exception/header/token/URL/源文本；部分读取不组成可发布授权，CI `FINALIZE_OBSERVATION` 最终重核撤销则抛弃源结果；宿主独立一时 grant 不可伪造，HostOnly 路由继续拒绝。**不要用本地合成 canary 的缺席推导全面 DLP 认证。**
3. **超时、限额、数据不完整：** 一旦 CLI/Provider 大小、分页、来源数量、时间预算越界，则拒绝并保留实际 attempted/valid-result 差别；保留“处理尝试过、是否发生副作用未知”的信号，不自动再执行有副作用操作。`success` 或 exit `0` 不得提升为业务完成。非 Router 的 direct-main 必须单独做授信和边界审计。
4. **真实安全事故：** 停止外部推送并保存由宿主审查过的非敏感诊断和既有 ledger/outbox 原始历史；将副作用归类 `UNKNOWN`，经独立授权人查证后再决定是否重试。禁止用 fixture 构造组织真实授权证明。

## 最终用户辅助的现场统一验证（全部 NOT_RUN）

在有**独立合法授权**的目标宿主上进行，并仅使用人工许可的测试凭据/隔离目标。记录真实日期、运行平台、二进制版本、操作者批准范围、测试前后外部状态、凭据/源/策略 pin（不上传密钥）、退出码与签名审查记录：

1. **真实断网：** 分别以无网络、DNS 失败、TLS 握手/证书异常、socket timeout、429/5xx、重定向、重试失败条件实测 GitHub/GitLab provider，只对**授权的只读 GET**进行测试。记录未发生额外 URL/方法请求，尤其不得修改 Issue 或生产记录。真实 HTTP、代理和重定向行为不允许被假响应替代。
2. **保密/权限：** 使用独立颁发的只读凭据、撤销中途授权、可审计出站过滤器和经过许可的合成 PII/secret，检查 JSON/stdout/stderr/日志/outbox/文件与 HostBridge 边界；审查从原生 PS7 `ces-v5.ps1` 到各 Handler 的最终输出不会回显密钥、私人文件路径、Patch 或报告原文。尤其必须核对当前企业 actor、role、source、credential、signed grant、revocation，而非单看程序布尔声明。
3. **资源：** 真实 OS/磁盘/网络配额、超时进程树清理、恶意无穷 stdout、1MiB+ Provider 流、巨大 JSON、多页、并发、损坏私有数据和 NFS/多宿主；**目前 STDOUT scratch 文件先写后测**必须明确评估。跑 E63–E66，再决定是否需要资源 guard 进一步修复。EC248 的 CodeShow k>56/大图保护在其独立轮施工。
4. **原生回归/端到端：** 完整原 R150 `scripts/ces.ps1` 与 **15 项 Smoke**、真实 PowerShell7、可写权限最小化的 DocsOnly 私有仓隔离、Issue GET/POST 只读/新建界限、Delivery/Knowledge/Quality 授信、EC242 已固定的 112 Schema 和 B001 源缺口；原仓 `.git` 链接 worktree 管理项可能更改，须区分业务源/index/refs 与 `.git` admin 元数据；最终移交阶段统一签字。

本轮结果不可用于替代在线/企业/原生/宿主验收。**EC246** 是另一个后续施工回合，本文不提前实施。
