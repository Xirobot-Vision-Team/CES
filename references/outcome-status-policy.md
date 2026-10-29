# EC243 · 统一错误码与覆盖状态（V5.53 / R243）

本契约仅适用于**显式选择的新 Python / `ces-v5.ps1` RequestPath 分发**，不更改原始 R150 PowerShell CLI、原始 15 个 Smoke，也不直接改变旧 Python 业务模块的返回值。`construction/outcome_consistency.py` 是所有新统一路由的唯一归一化实现。输入状态是处理器**未经独立证实的陈述**；归一化只确定如何向调用者安全呈现，不提供信任提升。

## 五类稳定状态及进程退出码

| V2 `status` | 统一 CLI exit | 语义 | 能否宣称业务完成 |
|---|---:|---|---|
| `partial` | 2 | 返回了有界合法 JSON、局部观测或未验明的完成声明；不证明整体覆盖 | 否 |
| `offline` | 3 | 处理器明确报告断网或网络被禁用；不代表目标不存在 | 否 |
| `denied` | 3 | 权限、操作范围、未注册模式、旧 CLI 专用入口或独立宿主门槛拒绝 | 否 |
| `invalid` | 4 | 请求或本地内容不满足契约 | 否 |
| `unavailable` | 5 | 资源不可用、错误输出、异常终止、未知结果、证据源/记录不可信 | 否 |

**退出码 0 只供 `--list-routes` 枚举元数据使用**，不代表曾调用处理器。该命令返回不同形状的只读 route inventory，不属于 Action V2 result envelope。历史模块自身仍可能输出 `status: success` / `exit_code: 0`；路由必须返回 `partial` / 2 并保留原始值在 `handler_result`、`handler_status`、`handler_exit_code` 中。客户端不能从后者推断新权限或业务任务成功。

遇到 `success` / `ok` / `completed`、模式已注册、可读 Schema、创建了私有 CES 元数据、验出 DAG、Due 判定为 DUE，统一**不**承认业务完成。遇到明确负面处理器退出码 3/4/5，负面结论优先于子处理器的“成功”文字；子状态与退出码冲突时 `handler_outcome_consistent=false`，原因 `ROUTER_HANDLER_STATUS_EXIT_INCONSISTENT`。CLI 进程退出与 JSON 自报 `exit_code` 不一致、非法 exit、超时、非 JSON、重复/大小写碰撞键、过大输出均拒绝为 `unavailable` / 5。不会从 `reason_code` 字符串进行模糊关键词猜测，避免源文本误触发。

## 部分覆盖与调用结果

`coverage_assessment` 是独立于 `status` 的四值陈述：

- `NOT_OBSERVED_NO_VALID_HANDLER_RESULT`：根本没拿到可保留的处理器 JSON；`handler_result=null`，包括未注册、独立宿主拒绝和输出解析失败。
- `DECLARED_GAPS_UNVERIFIED`：处理器的已知 `coverage` 字段明确为 `false`；`coverage_missing_claims` 只输出经审查的固定字段名，绝不转发路径、补充文本或凭据。
- `PARTIAL_OR_INCOMPLETE_UNVERIFIED`：处理器明确返回 partial 类状态或自述缺项，但不冒称确定范围之外的事实。
- `NOT_ATTESTED_BY_ROUTER`：没有可依据的明确覆盖声明，或者声称完整，但统一路由无法独立证明。

已审查的缺项字段：`source_identity_bound`、`path_inventory_complete`、`content_released`、`content_complete_for_selected_source`、`source_currentness_proven`、`remote_delivery_proven`、`provider_actor_verified`。这些仅是**原处理器自述字段**，`true` 也不是路由端的认证；遗漏为 `unknown`，绝不能当作 true。部分缺项可在 `status=invalid` 时一同呈现，仅作诊断。

`handler_attempted=true` 表示至少启动了 CLI 子进程或进入了 API 方法调用；**不能证明执行了任何有权限的动作**。`handler_invoked=true` 保留 EC241 的历史含义：获得了合法可保留的 JSON 对象（即使原结果是失败）。发生超时或不符合 JSON 契约时可以 `attempted=true / invoked=false`。不调用处理器时二者均为 false。输出还固定 `business_effect_verified=false`、`permissions_granted_by_router=false`、`external_identity_authenticated_by_router=false`、`tasks_advanced_by_router=false`、`native_powershell_runtime_tested=false`。

## JSON 契约及兼容

从本轮起，新响应标识为 `ces.unified_action_router.v2`，包版本 `V5.53/R243`。严格的 Draft2020-12 结果契约为 [`unified-action-router-result.v2.json`](unified-action-router-result.v2.json)；它限制状态、退出码组合、处理器是否返回结果、权限证明布尔量及覆盖字段。原 [`unified-action-router-result.v1.schema.json`](unified-action-router-result.v1.schema.json) **字节级保留**，属于 EC242 112 个固定 SHA 的历史 Schema 检查集。V2 为新独立 JSON 契约，未冒充重新审查过的旧目录；特意不使用 `*.schema.json` 后缀，避免 EC242 旧 `audit` 将本次新文件误判为 112 个冻结旧文件的未登记漂移。依赖 V1 响应形状的客户端需要显式升级读取器，不能静默把 v2 当作 v1。

`ces-v5.ps1` 的新请求桥接校验 V2 Schema 身份、包版本、五类 status、退出码和不虚构的权限字段；没有 `-RequestPath` 时仍走原始 `ces.ps1`，不转换旧业务响应。在此施工环境未实际运行 PowerShell7；对应原生行为留待最终用户统一验收。

## 例子和调用

```bash
python3 -I scripts/ces_router.py --list-routes
python3 -I scripts/ces_router.py -Action Due -Mode Evaluate -RequestPath /absolute/path/to/request.json
python3 -m unittest discover -s construction -p test_outcome_consistency.py -v
```

对 `Due` 的合法日历条件，即使内部返回 `partial` + `DUE`，新路由也只能返回 `partial` / 2；非法 cadence 返回 `invalid` / 4。`SchemaReview/Audit` 找到已知旧 Schema 的 `$id` 或根版本问题时返回 `partial` / 2，不能当成全域迁移已通过。`Cycle/Summary` 遇到不存在或不可信的 Run 返回 `unavailable` / 5，不能当成空的已完成任务。真实企业身份、独立源码/证据签名、宿主授权、实际写入、断网行为、Windows/macOS/PowerShell7 和原生 15 Smoke 需要用户最终协助验收；本轮的离线状态分类使用明确标记的合成测试结果，而非真实 provider 断网的验证。
