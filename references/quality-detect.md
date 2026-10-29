# EC-181 — QualityDetect: 授权工作树配置清单（V4.91/R181）

此轮交付的是**真实可运行的独立 Python 只读检测器** [`construction/quality_detect.py`](../construction/quality_detect.py)，返回 [`ces.quality_detect.v1` 严格 JSON](quality-detect-result.v1.schema.json)；**不是**主 PowerShell `QualityDetect` 新路由，也不是 CI reader、测试运行器或安全执行环境。只识别授权的**本地文件名/配置语法声明**，即使是正确解析的配置，也不会确认 Git 当前 commit、依赖已安装、命令存在或可运行、更不会声称测试通过。

## 授权与调用边界

只支持明确传入的**单一** `WorkingTree` 绝对、规范化、无 symlink 路径；不使用环境默认工作目录、不读取上次缓存或用户提供的 `CodeInsight` JSON 来代替真实文件。`QualityDetector.observe_root(repo_root, authorize_observation=...)` 须通过独立可信回调才可读取该根的 POSIX inode/device/mtime/ctime 并创建本地 `ces.quality_source_pin.v1`；这是**最多 300 秒有效的本机目录观察**，并非已认证 Git SHA 或人类权限凭据。

`QualityDetector.detect(repo_root, pin, candidate_paths=[...], authorize_source=..., authorize_path=...)` 在开始时核对源模式、根字符串、完整 pin、时钟允许偏差；随后要求另一个**独立源范围授权**，且对每个候选先要求**独立文件级授权**（包含精确路径、source pin 摘要和 `READ_CONFIG_BYTES` 或 `READ_CONFIG_METADATA` 目的）才可尝试打开。回调必须由宿主在其可信授权上下文实现；任意用户自己编造的 `True`、pin 哈希或 CLI 标志**不能证明帐号身份、第三方权限或仓库来源**。请求拒绝不输出已经读取的部分文件或工具。

简单手动命令（会读取**明确点名**的授权配置；不联网、不创建文件）：

```bash
cd ces
python construction/quality_detect.py \
  --repo-root /absolute/unsymlinked/source/tree \
  --path pyproject.toml --path pytest.ini --path package.json \
  --allow-root-observation --allow-config-metadata --allow-config-bytes --json
```

- `--allow-root-observation` 是独立的本地根读取许可；`--allow-config-metadata` 只授予明确列举文件的只读元数据及源范围许可；`--allow-config-bytes` 另授予 TOML/INI/JSON 配置字节读取许可。省略任意所需许可返回 `unavailable/5`，而非试探其他路径。**CLI 标志代表当前操作者在该进程主动允许本地读取，并不认证远端/真人身份。**
- 无 `--path` 时 CLI 拒绝。最多 64 个**显式**安全路径，路径最深 4 个组件；允许在自选工作区如 `apps/client/package.json`、`.github/workflows/test.yml` 查某个文件，不枚举整个目录或自动搜索仓库。不要把本模块当做自动递归语言识别。
- 只接受固定白名单：`pyproject.toml`、`Cargo.toml`、`package.json`、`pytest.ini`、`tox.ini`、`setup.cfg` 等固定解析器文件；`go.mod`、`pom.xml`、`build.gradle*`、`Makefile`、`tsconfig.json`、锁文件和 CI workflow 文件等**只读元数据**。不接受 README、任意 shell 文件、仓库脚本、`.git`、`node_modules`、虚拟环境或隐藏的敏感目录。`setup.py`、`gradlew`、Gradle/Maven/Makefile 和 CI/YAML 只看文件元数据，**绝不导入、解析其命令或运行。**
- Python `tomllib`、无插值 `configparser`、拒绝重复键的 JSON 只解析固定允许的**配置字段**；`package.json.scripts` 的 `test/build/lint/typecheck/check/format` 最多披露**键名**，从不读取出现在结果中的 script 内容、不拆解 shell、不将其当可执行配方。损坏/不可支持的配置标 `MALFORMED_CONFIG` / `PARSER_UNAVAILABLE`，不会宣布有可运行工具。`.github/workflows/*.yaml` 及 `.gitlab-ci.yml` 的出现不表示 CI 工作流真的执行。

一个返回 `partial/2` 的 JSON 中：

- `files[]`：每个被批准候选的 `PRESENT/ABSENT` 和解析/元数据状态、受限字节长度。只在被额外批准读取 TOML/INI/JSON 内容时输出文件 SHA256；元数据文件 SHA 是 `null`。
- `languages[]`、`tools[]`：可溯源的**配置痕迹**；`installed=NOT_CHECKED`、`command_usable=NOT_CHECKED`、`executed=false` 永远不升级。
- `profile_hints[]`：如 `python.pytest`、`node.vitest`、`python.ruff` 的**非命令字符串标识**；不给出可复制运行的 shell/argv。后续 EC186 的执行前需全新授权、隔离和环境证据，不能直接执行本结果。
- `coverage`：仅 `inventory_complete_for_explicit_allowlist=true`，全仓覆盖/有效 Git SHA/整个树当前性/跨文件原子性/工具安装、实际命令/CI结果/测试全部明确 `false`；即使 `files=[]`（授权拒绝）也绝不声称“没有质量问题”。
- `effects` 四项固定：`read_only=true`、`executed_commands=false`、`writes_performed=false`、`network_access=false`。

## 文件系统防护及仍有风险

- 仅 POSIX 且有 `openat`-式 dirfd、`O_DIRECTORY`、`O_NOFOLLOW`、`O_NONBLOCK` 才运行；其他平台返回 `unavailable`，**不回退到不安全普通 `Path.read_text()`**。对用户指定的 root 和每级候选组件不跟随 symlink、不接受 `..`/绝对候选/控制字符/混淆大小写列表，禁止硬链接、多类型节点、FIFO/设备。每个文件读取前后核对 inode/device/大小/修改时间等，连同目录路径的二次相等核验及根目录的名称重新打开校验；失败即丢弃整个响应。
- 允许 TOML/INI/JSON 单文件最多 128KiB、所有解析字节合计最多 1MiB；仅 stat 而不读的锁文件/CI/未解析配置最多 128MiB 元数据声明，64 个显式路径，不做磁盘递归。目录大小、mtime 和 inode 的约束旨在发现常见竞争而非证明不会出现恶意同 UID 攻击；极端 ABA rename、在同一时钟粒度内伪造 stat、共享/网络文件系统、case-insensitive POSIX、macOS 特殊语义等**仍需最终用户现场验收**。
- stdout 中没有源码正文、脚本命令、包脚本值或绝对路径；`local_root_pin_sha256` 和 `inventory_sha256` 仅是本地可重算摘要，**不是** HMAC、签名、外部身份或完整树快照。手动调用 CLI/测试时，操作系统本身可能更新文件 `atime`；`writes_performed=false` 指模块不调用业务/CES/远端写路径，**不保证全系统零 atime**。
- 不支持 `DeliveredTarget` 或 `ProposedPR` 作为本地仓库直接扫描证据，不从离线旧记录推断目标已交付。对生产工作树请在目标 OS/权限/仓库身份隔离环境最终验收；EC182 之后才能进入真正只读 CI 观测，EC186+ 才会设计执行权限，仍须独立批准。

## 离线开发校验与后续交接

本轮用于功能迭代的开发自检：`python construction/test_quality_detect.py -q`，合成临时目录和严格 JSON Schema；详见 [`fixtures/ec181/README.md`](../construction/fixtures/ec181/README.md) 及 [`EC-181.md`](../EC-181.md)。这**不等于**原 PowerShell7、15套 Smoke、Windows/macOS、真实 Git/CI、跨OS hostile FS、E63～E66 性能、原始上游 B-001 补证或全功能联合验收。

下轮 **EC182** 仅 `QualityReadCI` 只读来源抽象/权限/时间及真实可验证结果边界；**不可**将本轮本地配置提示伪装为远端 CI 结果。
