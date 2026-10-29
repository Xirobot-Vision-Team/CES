# CodeShow Sequence — current entry guide

**R150** already includes selected historical CodeInsight Sequence and advanced original SCC directed-link removal/cardinality analysis through **k=56**. This existing source is preserved intact in `scripts/` and must not be silently deleted or advertised as having passed runtime tests.

`CodeShow -Mode Sequence` reads explicitly ordered **2..12** saved CodeInsight records; its analysis concerns recorded evidence structures, not software fault severity or proof of code remediation. Sequence order is caller-selected, not verified chronology. Exact anchor identity is stronger than matching headings or display names.

Sample read-only invocation:

```powershell
pwsh -NoProfile -File ./scripts/ces.ps1 -Action CodeShow -Mode Sequence -RepoPath <path> -SequenceRecordIds 'ci-<first>,ci-<second>' -Json
```

On plan-revision construction EC-151..250, **freeze k=56** and prioritize missing product actions. Do not delete old child output fields, mutate saved CodeInsights, assume E63–E66 performance, or infer a physical defect probability from cut combinations.

Original detailed historic reference: [history/legacy-docs/code-sequence-R150.md](../history/legacy-docs/code-sequence-R150.md). Older release-specific notes live under `history/legacy-rounds/`. Consultation is on-demand only.

## EC-154 只读静态依赖与公开字段冻结证据（施工包V4.64/R154）

- 运行`python construction/sequence_audit.py --k 56 --json`查询k56源码定位、直接k55依赖、公开子字段和`counts`契约；`--list`列出全部k1～56、`--risk PERF-PARENT-REPLAY`定位静态重放风险、`--check`对照[`LEGACY_SEQUENCE_AUDIT.json`](../construction/LEGACY_SEQUENCE_AUDIT.json)冻结审计快照。上述工具是CES施工工具，不是新的PowerShell Action。
- k1～56模块与原输出路径通过原`codesequence.ps1`调用赋值静态还原；k38～56存在19个显式父级函数重放/序列化JSON比对，**不是**k1～56全链条的实际执行/递归次数测量。E63～E66边处理存在高位索引特殊路径，但运行时间/内存未实测。
- 原PowerShell与Smoke源文件未改；静态冻结数据可以发现字段/模块/源SHA漂移，不能替代真实PowerShell编译、语义、性能或安全验收。有关完整风险与核对界限见[`EC-154.md`](../EC-154.md)。
