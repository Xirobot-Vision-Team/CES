# README 增量维护

README 维护是知识发布流程的一部分，默认开启，可在外部 profile 关闭：

```json
{
  "knowledge": {
    "readme_maintenance": { "enabled": false }
  }
}
```

未配置时按 `enabled=true` 处理。这个开关启用发现、来源绑定和增量维护；实际
写入仍需 `repository_docs.allow_write`，提交/推送仍需既有独立授权和配置。
配置模板不会因此默认允许写入、执行或推送。`doctor` 显示实际开关状态。

## 自动触发与功能定位

每次 `knowledge prepare` 随知识输入发现已跟踪 README：根目录面向仓库入口，
与 `.sln`/`.slnx` 同目录面向解决方案，与 `.vcxproj`/`.csproj` 等工程文件，或
CMakeLists.txt、pyproject.toml、package.json、Cargo.toml、go.mod、pom.xml、
Gradle/Meson 描述文件同目录面向项目。根目录可同时承担仓库与项目/解决方案角色。
识别大小写及 README.en.md 等变体。跳过 CES 成品目录、常见依赖/构建目录；
没有同目录描述文件的非根 README 标记定位缺口，不凭目录名称猜测功能。

只选择本轮代码或构建来源所在范围的 README。只选 README/知识文档而没有代码
或构建来源时，不编造功能更新。尚无 README 的工程目录会报告缺口；当前功能
维护现有 README，不擅自创建覆盖语言、目录职责均不明确的新文件。

Codex 阅读真实 README、同目录构建描述、相关代码和原知识章节，判断功能定位
及变化影响，撰写 `ces.knowledge_draft.v1` 的 `readmes` 数组。不是把章节全文拼接
成 README，也不根据文件名、退出码或 Build 成功生成算法/运行正确性结论。
仓库入口侧重用途、导航和边界；解决方案侧重组件及构建关系；项目侧重职责、
接口、依赖及已核验用法。证据不足的描述保留限制。

## 来源绑定草稿

`knowledge prepare` 返回的输入含 `readme_maintenance.targets`、定位角色、范围、
相关来源、当前内容哈希和缺口，参与原 `binding_sha256`。草稿与知识章节同批提供：

```json
{
  "readmes": [
    {
      "path": "src/widget/README.md",
      "action": "update",
      "reasoning": "根据本轮接口来源和知识章节核对组件职责，更新受影响说明，保留人工介绍。",
      "markdown": "## 功能与使用边界\n\n这里由Codex根据真实实现撰写有来源依据的功能介绍，保留未经运行验证的限制。",
      "knowledge_paths": ["widget.md"],
      "citations": [
        {"path": "src/widget/widget.cpp", "line_start": 1, "line_end": 2, "quote": "实际来源中的字面引用"}
      ]
    }
  ]
}
```

示例须放入正常知识草稿的同级字段；原 schema、input_binding_sha256、chapters
保持。每个更新必须引用本轮明确选择、位于该 README 范围的真实来源，并关联
本批已审阅、同范围的知识章节。用 `action="unchanged"` 和引用/理由表示评审后
无需改变。不提供条目则保留旧文件并返回 `readme_draft_missing`，不能宣称已维护。
老知识输入没有 README 绑定时返回 `input_upgrade_required`，重新 prepare 后再更新。

`knowledge publish` 自动校验 README 草稿，与知识章节一起预览/写入并按已有授权
触发文档发布，无额外定时器或单独测试程序。正文、引用、关联知识和定位均未变
时不会只为 HEAD 或执行时间变化重写 README。固定来源引用可保留原提交。

## 人工编辑保护与 Git 范围

首次在现有文件末尾追加明确维护区；之后仅更新该区：

```markdown
<!-- ces-readme:start -->
来源绑定的功能说明、知识导航和代码引用。
<!-- ces-readme:end -->
```

首次追加保留原人工字节，包括 BOM、换行和尾空白。已有 CES 标记却没有托管记录，
标记损坏/重复、成员改过维护区、未提交 README 编辑、输入后文件变化、符号链接
及路径穿越均停止，不静默接管。已提交的人工区变更允许作为下一轮来源保留；
它本身仍是成员工作。维护区外的文字不会与自动更新合并成机器人生成提交。

托管记录位于配置成品目录的 `readme-manifest.json`，沿用同一个文档 manifest、
外部知识版本和发布账本。Git 仍使用独立索引；唯一扩展是允许清单中精确命名的
README 维护区变更与 `docs/ces` 成品一同提交，禁止其他根目录文件、业务代码、
日志、配置或缓存混入。远端推进、成员暂存修改和并发文件变化会停止。
文件替换逐个原子完成；批次中断保留可见状态与计划，须对账后恢复，不reset/强推。

README 自动提交的工作审计排除还会核对仓库身份、回执/机器 trailer、文档清单及
README 子清单内容哈希，并逐字核对父提交人工区。混合人工 README 修改或业务
提交保留；证据读取/核验失败也保留并报告。旧归档不删除，不递归计算自动文档工作量。

此实现是助手编排的来源绑定维护，不包含模型 API。没有 README 草稿的无人值守
Python 调用只报告待撰写缺口；默认开启不意味着能够凭空生成可信的功能说明。
