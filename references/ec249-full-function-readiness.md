# EC249 — 全功能施工完成判定：真实功能与最终验收门槛

**完整工程包 V5.59/R249；只施工 EC249。当前判定：`FULL_FUNCTION_NOT_COMPLETE`。**
这不是 EC250 候选冻结，也不是用户辅助联合验收结果。施工记录 99/100、已有处理器源码、固定路由登记和本地 fixture 运行不能相互替代。

## 即刻可用的只读功能

```sh
cd ces
python3 -I -B construction/ec249_completion/decision.py --format json > /tmp/ces-ec249-review.json
# 注意：正常发现产品未完成时，退出码故意为 2；输入源证据不自洽返回 4
python3 -I -B construction/ec249_completion/decision.py --format markdown
python3 -I -B construction/ec249_completion/test_decision.py
```

脚本读取**本工程内**的固定计划、构建元数据、产品矩阵、EC246 74 路由目录、EC244 307 项 SHA、本地原始 15 Smoke SHA 清单以及 EC247/248 有界本地结果，生成 100 轮逐条证据状态和明确的缺口判定。该 CLI 没有 `--root` / 动态模块 / 用户权限令牌 / 网络入口，不执行任何 Router handler、PowerShell、Git、QualityRun、AI、发行或发布动作；标准输出仅含本地源码/计划目录相对路径。若源码漂移、引用丢失或状态矛盾则阻断并标注，绝不升级为 `PASS`。

**当前可复核的范围：**计划连续 EC151–250；EC151–249 标记 `IMPLEMENTED_PENDING_FINAL_ACCEPTANCE` 仅代表对应施工轮有记录，EC250 保持 `PLANNED`。本地锁源 307/307，旧 15 Smoke 文件 SHA 15/15，仅代表文件未发生可观察的本地修改；74 条固定路由 16 Native + 39 CLI + 7 API + 1 Preview + 11 Host Required。旧 16 Native 是原 PowerShell 入口，不是当前新 Router 的请求文件接口。

## 不得跳过的实施缺口

| EC249 缺口 | 现有事实 | 性质/后续工作 |
|---|---|---|
| G249-HOST | 11 条 HOST_REQUIRED 模式在独立 Router 中始终拒绝；无独立宿主桥 | **功能实施未接通**，不可将存在 Python handler 文件等价为完整路由 |
| G249-QUALITY | `QualityRun/Execute` 为 HOST_REQUIRED，EC186/187 是安全前检和受限执行模块，不证明本产品当前宿主可分发实测任务 | **功能实施与宿主依赖**：实现且验证受审隔离执行代理 |
| G249-WRITES | `IssueCreate/Create`、`DeliverySend/Send`、`ReportPublish/PrivateTest`、`DocsOnlyPublish/LocalSandbox` 等涉及外部状态/仓库路径只能由独立宿主批准确切目标及一次性动作 | **功能/授权缺口**，严禁为通过验收而绕开拒绝 |
| G249-CYCLE | EC233 Next 可给出下一步候选；EC235/236 持久化拒绝与只读恢复；EC239/240 有边界规划与同槽冲突守卫，但无完整宿主调度/AI/CLI 实际推进 | **端到端实施未闭合**，需要获批的执行路径或明示缩减原计划 |
| G249-NATIVE | 原 15 PowerShell Smoke 0/15 实际运行；CodeShow/Sequence E63–E66 未真实测量 | **现场验收缺口**；不能称 native 稳定或性能改善 |
| G249-PROVIDER | GH/GL/CI/Issue 和 Delivery 的实际授权、账户、source/actor/recipient 上下游身份尚无真实验证 | **外部集成/现场验收**，不以 synthetic fixtures 代替 |
| G249-OS | Windows/macOS/Linux、进程树/磁盘/保密、Git worktree 管理数据和业务仓源/index/refs 非变更尚无真实证明 | **安全/OS 验收缺口** |
| G249-UPSTREAM | 原冻结 V3.10 与原 ROUNDS.json 无经认证原始资料，B-001 仍 Open | **原规格出处缺口**，需要来源/版本及人工映射 |
| G249-INDEX | 历史规划条目中部分轮次仅有 EC 记录而缺 plan 的直接 artifact 列表 | **可追踪性改进**，不能据此推断那些轮次缺代码 |

## 出口与用户后续决策

- 本轮的交付是可复现的**保守完成判定工具+报告**，不是许可凭据、业务系统或新路由；本地源码一致不等于上游来源真实。
- 按原 100 轮方案，**未达全功能施工出口时，不得进入 EC250 冻结/最终验收**。EC250 仍在计划中，但当前冻结门槛锁定为 `BLOCKED`。不偷偷添加 EC251+、不私自降配功能范围，也不把过去 98 个“已施工”自动改为“验收合格”。
- 可先由负责人选择完成独立宿主、实际调度和隔离执行等残余功能，或者经明确审批将它们作为二期/受限能力并修订产品定义与轮次计划；之后再判断是否可施工 EC250 候选包。选择、方案修订和权限授予都不由工具自动作出。
- 本地运行 `review` 的结果位于 `construction/EC249_COMPLETION_DECISION.json`；其中 `per_round` 覆盖 100 个 EC，`gaps` 给出审查理由、已有证据和关闭条件；本轮结果仍标记 `may_enter_final_acceptance=false`、`may_freeze_ec250_candidate=false`。

## 累积的最终用户辅助验证（现在**不执行**）

PowerShell7 与 15 原 Smoke / E63–E66 大图、真实 Git/OS 进程与资源边界、Provider 批准的非生产帐号及失败/重入、企业 host/actor/source 独立签发、Quality 真实执行、Issue 仅新建不修改已有项、Delivery/DocsOnly 发布隔离、NFS/多主机并发、全链路数据与权限、B001 上游规格核对。所有未做项目保持 `NOT_RUN` 或 `OPEN`，不伪造测试记录。
