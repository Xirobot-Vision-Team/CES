# EC332 两份独立 SHA 固定的 EC331 观察集合本地差异协议

## 适用范围与不可推出的结论

只比较**两份各自通过独立包外渠道固定整份原文件 SHA256 的 EC331 私有规范 LF JSON manifest**，每份 manifest 含 2–8 份 EC330 无签原报告的独立全部旧原件受信参数。程序先分别调用**真正的生产** `EC331.cross_reference`，其中每报告重演 EC330→EC329→EC328→EC294 的全部原签历史。不能使用旧 `.json` 终端输出充作签名证明，更不能将用户输入 SHA 字符串本身当作已经证明存在独立包外保管。

`left` / `right` 表示两个本地见证输入，**不**表示时间先后、远端删除/撤销或已成为赢家。所有成功核验的返回都是 `exit_code=2 / ...unresolved`，而不是远端成功。签名原件在集合中“未出现”只代表本地所见缺失，不代表签名撤销。

## 受信输入格式

**没有新权威清单格式。** 直接复用 [EC331 私有规范 manifest](ec331-offline-report-set-cross-reference.md) 的 `ces.ec331.externally_pinned_offline_report_set_manifest.v1`。每份：0600、规范 LF JSON（键排序、ASCII 编码、末尾换行）、最大 140,000 字节、2–8 条，每条具有 `report_file / expected_report_sha256 / comparison_inputs`。`comparison_inputs` 仍须完整提供与 EC330 验签对应的两账本/前账本/独立第八请求/争议案卷/原签两侧身份及受信源码路径+SHA，不允许在独立核验方复制 EC330 报告里的 untrusted source claim 作为“外部受信”输入。路径必须绝对、规范化、指向私有可读真实文件；两个 manifest 路径必须不同，可以拥有相同原字节 SHA 以证明零差异。

```text
python3 -I -B scripts/ces_cas_report_set_delta.py compare-report-set-observations
    --left-manifest-file /abs/private/left.json
    --left-expected-manifest-sha256 <LEFT_SHA_FROM_OTHER_TRUST_CHANNEL>
    --right-manifest-file /abs/private/right.json
    --right-expected-manifest-sha256 <RIGHT_SHA_FROM_OTHER_TRUST_CHANNEL>
```

统一入口：

```text
python3 scripts/ces_next.py audit-hold-report-set-delta DeliveryAudit ComparePinnedReportSetObservations
    --left-manifest-file /abs/private/left.json
    --left-expected-manifest-sha256 <LEFT_SHA_FROM_OTHER_TRUST_CHANNEL>
    --right-manifest-file /abs/private/right.json
    --right-expected-manifest-sha256 <RIGHT_SHA_FROM_OTHER_TRUST_CHANNEL>
```

统一入口的 `-I -B` 子命令路径固定；对未知 action/mode、缺 SHA、未规范化路径、企图包含 `--out`/签发参数或伪造成功安全字段 fail-closed。独立 CLI 也没有本地写或 signer 子命令。

## 输出字段与精确定义

成功 schema `ces.ec332.two_pinned_report_sets_local_delta.v1`：

| 字段 | 唯一正确解释 |
|---|---|
| `left_manifest_original_raw_sha256`, `right_manifest_original_raw_sha256` | **调用方声明**已受信的整原文件 pin，程序实际逐字节核对，程序不验证可信通道来源 |
| `same_manifest_original_bytes_at_two_distinct_paths` | 两独立路径的原 manifest SHA 字符串相同，不表示两次独立机构票数 |
| `left_observation_counts`, `right_observation_counts` | 每边 report 原行数、去重报告/账本/真实第九签名回执原 SHA 数量 |
| `report_original_observation_difference`、`ledger_original_observation_difference`、`signed_ninth_receipt_original_observation_difference` | 每类别仅输出三组**排序原 raw SHA**：`only_in_left_observation` / `only_in_right_observation` / `observed_in_both`，不存在按路径、无签文本或 signer 身份增票 |
| `combined_unique_*_count` | 同一原 SHA 在两侧或多文件中出现，严格一次 |
| `cross_input_only_ledger_pair_count` 与 `...relationship_counts / ...examples` | 只涉及一侧独有 ledger 和另一侧独有 ledger 的成对原件；单步真父原始 SHA / 双原签同父分叉由 EC331 保守逻辑判定；**共同前缀不推断跨两跳历史**。只显示前 24 例，其余仅分类数量 |
| `combined_distinct_signed_receipt_reused_ninth_role_groups` 与 `cross_input_only_ninth_role_reuse_groups` | 跨全部真验 SHA 不同原签回执的 signer/pub/nonce/decision/local path 重复；仅输出域分离哈希指纹和前 8 个 SHA，不回显真实 signer/plaintext 路径 |
| `both_ec331_sets_and_every_inherited_signed_history_genuinely_replayed`, `both_sets_original_source_report_and_manifest_pins_rechecked_after_union` | 只有实跑两次 EC331 全旧原签核验和跨两边最后重新读所有输入才为 true；模拟 fixture 只是在单测环境被局部 mock，**隔离真程序会拒绝** |
| `left_and_right_are_labels_not_temporal_claims_or_signed_precedence` | true 表示上述标签只指有限本地可见集合 |
| 所有 `*_proven` 远端/组织/机构字段 | 恒 false，不能存在 `winner`、`global latest`、远端 CAS 签收或真实实际 nonexecution 成功判断 |

跨集合 relationship 的原 SHA 对不超过 8×2×2 = 16 个每边独立账本、最多 256 个“仅并集可见”组合。每边 manifest 最多 8 报告、每报告两个源账本，每个源账本最多 16 条第九 signed receipt。输出原 JSON 上限 256,000 bytes，最多 24 个关系示例和最多 24 个 role 冲突示例。即便条目共享同一 ID，第九真签 SHA 不同才可列角色复用；一模一样原签回执复制绝不能产生新签名意见。

## 重放与错误语义

1. 独立检验左 manifest 的私有路径、外部原 SHA 和全部原报告/旧真签，并重读独立固定的原账本；其摘要与 EC331 已重算结果再核一致。
2. 独立检验右 manifest 的同一全套流程。任一 side 验签失败拒绝全部肯定结果。
3. 必须原第八签名请求、原争议/registry/序号/父与两个原子 head/目标 namespace/request ID **完整一致**，否则拒绝跨域比较；相同原 SHA 的不同副本账本内容也必须相同。
4. 按原 SHA 构造报告/账本/第九签名交差，分类仅并集新增可观察的 ledger 对及 signer 复用；不依据无签报告中单独的“成功”字段推断任何额外权威。
5. **完成合并之后**再从两边原受信参数核对**所有**当前/前置账本/第九签名原回执/旧原签渠道/父/第八请求/争议原件及 EC330 报告，最后重新读取两边 manifest 原 SHA 和原字节。中途变化即全批拒绝。
6. 回答 JSON 中不泄私有绝对路径、签名私钥或明文身份；`exit2` 局部未决，`3` 授权不足，`4` 输入非法/签名不符，`5` 依赖不可用；不产生 `exit0` 远端业务成功。

## 测试状态和最终累计验收

本轮新 `test_delta.py` **15/15 PASS**，本地第八/九 Ed25519 真实，继承 EC321 深层 EC317/318 模拟，不是生产全部 EC294→332 真实原签名样本。隔离 Python `-I -B` 对该 fixture 预期返回 `exit4`。真实独立 trusted SHA custody、实际机构身份授权、远端可线性化 CAS/WORM/签名 readback/实际 no-submission/latest/winner、生产无 mock 全历史、PS7 Smoke15、双物理机、跨 OS、Provider/CI/E63–E66 和用户终验均未证明。EC249 incomplete、EC250 blocked、B001 open、Quality PASS=false / final NOT_STARTED 不变。

[本轮施工](../EC-332.md) · [本机事实](../construction/EC332_LOCAL_REPORT.json) · [下一轮](../construction/NEXT_ROUND.md)。
