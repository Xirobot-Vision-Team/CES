# Issue追踪与修复闭环

入口：ces-product.cmd track。状态缓存位于state_root/issue-tracking/<repository_id>/；投影位于output_root/tracking/。仓库身份隔离，不含任何样本项目专用代码。

## 状态
open：尚无可核验进展。not_fixed：当前固定源码复核仍见问题。in_progress：存在处理评论/声明。fix_candidate：有PR或提交引用，未证明修复。closed_unverified：GitHub已关闭但未验证。resolved_verified：当前固定来源与必需测试满足评审要求。regression_suspected：复发待核验。unknown：读取失败/证据不足，不等于不存在。

## 流程与命令

默认 `issue_tracking.track_closed=false`：只主动跟踪仍为 open 的代码Issue。
同步中的轻量状态清单可记录已知Issue关闭或实际重新打开；已关闭后保留原始快照、
评审及事件历史，不抓取其评论、timeline、PR或源码，不因HEAD变化继续复核或提醒，
也不列入日报/周报的主动修复待办。关闭仍不等于修复已验证；closed_unverified
可作为历史状态保留，无须为了消除此标签主动追踪。当前状态页标记停止跟踪，
历史归档不删除。只有实际重新打开才恢复常规跟踪；用户另行明确要求复查已关闭
Issue时，可临时显式启用 `track_closed=true`，仍需独立来源/测试门，不自动授权重开。
    ces-product.cmd track sync --config <profile> [--execute]
    ces-product.cmd track status --config <profile>
    ces-product.cmd track history --config <profile> [--number <n>]
    ces-product.cmd track prepare --config <profile> --number <n> --path <source> [--path <other>]
    ces-product.cmd track test --config <profile> --number <n> --step <configured-step> --execute
    ces-product.cmd track review --config <profile> --input <input.json> --review <review.json>
    ces-product.cmd track transition --config <profile> --number <n> --state closed|open [--execute]

sync自动发现ces-issue指纹的自建代码问题，排除报告和PR；另可配置include_numbers。持久保存负责人、评论、状态、来源提交与实际关联PR（同仓head/merge/state）。首次基线和重复检查不刷屏；全部发现失败保留旧快照并记录错误，单条读取失败记unknown。同步有互斥锁，遗留锁不能猜测删除。自己的监控评论不算外部进展。

prepare绑定当前远端默认分支HEAD、Issue快照、Git blob和显式代码路径（最多16个）。Codex依据原问题及真实源码提交ces.issue_fix_review.v1：input_sha256、verdict（fixed/not_fixed/inconclusive/regression）、reasoning、verification_criteria、citations（path/line_start/line_end/quote）和test_receipts。

review重新核验来源内容、引用字面、Issue快照和远端HEAD后持久保存。它不独立证明语义，需区分静态审阅和运行复现。not_fixed/inconclusive允许来源绑定的静态复核；fixed必须匹配required_test_steps中全部真实成功回执，regression必须有当前来源失败回执。

test仅运行profile中明确配置的argv/cwd/timeout，默认预览、执行需--execute和allow_test_execution。记录日志、退出码、命令与提交；本地HEAD必须等于远端被评审HEAD，源码干净且前后不变。不自动pull/reset。未配置、失败、过期、日志或配置改变、错提交的回执都不能标fixed。缓存是本机未签名证据，不提供独立审批或可信硬件证明。

## 状态写入与提醒
allow_auto_close/allow_auto_reopen默认关闭。transition必须先有当前fixed/regression评审和必需测试，重新验证当前HEAD、Issue和回执，才给预览；执行还需独立启用，精确PATCH并回读。只有本流程自己的关闭/重开事件能承接该源码评审，最后sync确认。
stale_days与reminder_cooldown_days默认7天，从基线或最近实质进展计时。只@当前负责人，不因检查时间改变重复提醒。未知发送结果持久阻止重发POST，先远端对账；不能换天继续刷同一未知提醒。

## 报告与任务
新建Issue成功后自动同步；日报与周/月/年入口更新/引用追踪投影，报告快照不包含易变的检查时间，因此无变化不重复发布。documents可将问题状态导出仓库issues/README.md，Git提交推送仍需授权。
现有每日/每周任务执行sync和仍open问题的必要源码复核、报告联动，即使无新提交也同步状态。已关闭项仅保留历史；测试仍需独立授权。不新增定时器、不修改原执行时间。

## 验收边界
状态机测试只用隔离的内存远端和临时状态文件，没有创建临时Git仓库或假Issue。真实仓库同步和#3当前代码not_fixed评审已运行，没有为测试关闭真实问题。当前真实仓库未配置必需测试步骤，所以不能宣称修复已验证或自动关闭可实测通过。


## 仅Build的执行策略

独立项目测试入口与报告分析见[TESTING.md](TESTING.md)。项目测试报告Issue不属于代码问题追踪范围，也不自动满足修复验收。`track test`要求明确`run_runtime_tests=true`和`kind=test`配置，回执与完整步骤配置哈希绑定；Build步骤、缺少kind/配置绑定的历史回执均不能充当真实测试证据。历史记录保留，需要时在授权后重跑，不回填旧回执。

若execution_policy.run_runtime_tests=false，track test执行被拒绝。可在分析前实际Build并保存日志，但不能将其替代修复所需的运行证据，也不因用户已确认VS正常构建而自动关闭代码问题。源码同步允许已授权fetch/ff-only，禁止自动reset/stash覆盖编辑。
