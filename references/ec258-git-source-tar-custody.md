# EC258 — 本地 Git commit 到 QualityRun Source TAR 的逐字节来源保管

本功能是 **operator 主动执行的独立离线准备/复核工具**，不是新增原生 Router Action，不是持续驻留的 Git/CI 认证服务器，也**不会自动强制旧 EC252–257 入口调用校验器**。它补足 EC252 把 Source TAR 本身固定到 SHA256、却无法证明 TAR 中具体字节出自哪个 Git tree/blob 的缺口。EC258 在可信本地 Git object store 内实现逐对象重新计算哈希；**远程 Git 仓库、commit 签署人/审核人/企业身份、所选文件是否有权限用于执行仍需其他独立证明**。

## 运行条件与输入约束

1. 必须是 Linux 上的**非 root 专用操作员 UID**；装有可信、审计过的 `/usr/bin/git`、Python 3。工具使用固定参数、受限环境执行只读 `rev-parse` 和 `cat-file`；不会运行构建脚本、Git hooks、外部网络或 working tree 中的可执行文件。Git 可执行文件、Python 解释器及宿主本身的完整性由操作员保证；本轮没有它们的独立签名证明。
2. `--repo` 指向由此 UID 拥有的、权限 `0700` 的**实际 checkout 根目录**，包含普通目录型 `.git/`（亦须 `0700`）。路径必须是正规绝对路径、所有父目录不得无保护地对其他用户可写、不得经 symlink 或外部 alternate object store / linked Git commondir。**不支持 bare repo、linked worktree、分包外来对象、Git 替换对象或来源自动 clone**。未被提交的 working tree 变更**一律不会进入 TAR**。
3. `--allowlist` 是**另外经人工审核批准的私有 `0600` JSON 文件**，置于当前 UID 拥有的私有 `0700` 目录（不能放 CES Skill 工程包）。字段必须**恰好**为 `schema`, `commit_oid`, `source_paths`，commit 必须是明确的完整 SHA-1 40 hex 或 SHA-256 64 hex，**不接受 `HEAD`、分支或 tag 作为执行时变化的引用**。`source_paths` 必须 ASCII、升序、唯一、纯相对规范路径、明确每个要打包的**已跟踪 regular file**；不会因为某目录加入列表就递归导出。最多 2048 文件、每项最多 8 MiB、总解包数据最多 32 MiB，TAR 最多 16 MiB。
4. `--output-dir` 是**独立空 `0700` 私有目录**，既不在仓库内也不在 CES 工程包内；最终输出 `source.tar`（未压缩 USTAR）与 `source.custody.json`（文件和 commit 的 hash 对照），都是禁止覆盖、受限 `0600` 的新文件。写入需要全量 `fsync` 和目录 `fsync`。如果中途崩溃产生孤立文件，绝不可当作已成对出具的批准文件；隔离并人工处置。
5. 拒绝 TAR symlink、hardlink、device、PAX 扩展、Git submodule、Git symlink、绝对路径、`..`、`./`、双斜杠、过深路径以及 `.git/.ssh/.aws/.env/...` 等高风险秘密路径与常见密钥扩展名。**这不是通用秘密扫描器**，仍需人工检查 `source_paths`、源码内容、版权和执行同意。

## 示例 allowlist（需替换为你的真实 commit SHA 和准确文件路径）

```json
{
  "schema": "ces.ec258.git_source_allowlist.v1",
  "commit_oid": "0123456789abcdef0123456789abcdef01234567",
  "source_paths": [
    "pkg/__init__.py",
    "pkg/check.py",
    "pytest.ini",
    "tests/test_check.py"
  ]
}
```

路径必须有字典序且全是文件；示例 Git OID 只是占位，**不可直接作为授权**。先取得操作员独立审核/确认的准确完整 commit hash；不要自动将 `git rev-parse HEAD` 的输出当成审过的来源。

## 生成、独立复核和现有 EC253 票据绑定

```sh
python3 -I -B construction/ec258_git_tar_custody/custody.py prepare \
  --repo /srv/operator/private/git-checkout \
  --allowlist /srv/operator/approval/selected-files.json \
  --output-dir /srv/operator/private/selected-source-20261024

python3 -I -B construction/ec258_git_tar_custody/custody.py verify \
  --repo /srv/operator/private/git-checkout \
  --allowlist /srv/operator/approval/selected-files.json \
  --source-tar /srv/operator/private/selected-source-20261024/source.tar \
  --receipt /srv/operator/private/selected-source-20261024/source.custody.json
```

`prepare` 与 `verify` **返回 `partial/2` 表示本地内容保管链已执行**，而非质量 PASS；失败是 `unavailable/5` 和固定原因码。工作树 dirty 不会覆盖 Git object。工具从明确 commit 读取并复算 `commit→root tree→selected subtrees→blob` 的 Git 对象 ID，复算每个文件 SHA256，最后由**确定性 USTAR** 产生 TAR 字节和包含逐文件模式/路径/哈希的记录。`verify` 重新读取 Git objects、批准白名单、私有 TAR 与 receipt，要求**字节级匹配**，拒绝任何增加、删减、替换、错误哈希、过期/已变动的 allowlist。EC252 还会在执行前和执行中独立复核政策与 TAR SHA256，并安全重新解包。

给原 EC253 **双签名固定 profile** 与操作员 policy 时可以执行额外绑定检查：

```sh
python3 -I -B construction/ec258_git_tar_custody/custody.py verify \
  --repo /srv/operator/private/git-checkout \
  --allowlist /srv/operator/approval/selected-files.json \
  --source-tar /srv/operator/private/selected-source-20261024/source.tar \
  --receipt /srv/operator/private/selected-source-20261024/source.custody.json \
  --ec253-policy /srv/operator/approval/ec253-policy.json \
  --profile-id python.pytest
```

额外检查要求 EC253 policy 里的 `source_tar_path` **恰好**指向同一路径、`expected_source_tar_sha256` 与本次 Git 构造出的 TAR 匹配，并用**既存 EC253 代码**核验针对该 profile 的两个独立有效签名票据及 Source pin 一致性。它**不**根据 Git commit 擅自推导或更改 EC186 opaque `authorized_source_pin_sha256`（原 WorkingTree 签名仍须单独取证）；也不把本地 MAC 和 blob hash 描述成来自远端组织的密码学证明。

若批准白名单、Git 数据、签名、镜像或原始授权有变，**重新做一次获准的 prepare+verify 并签发新的运行策略/票据**，不要更改旧 TAR 或已有 receipt，也不要重用已经消费的 Lease。复核之后开启原 EC257 严格入口，需要另由操作员配正确的、同 SHA 的 EC253 `source_tar_path`/policy；**EC258 不注册服务、不会替代/放松原宿主的私有策略、cgroup、限额或 Podman 清理门禁**。

## 建议的现场验收清单（未在施工环境执行）

- 真实人工授权：独立核对本地对象库来自**正确 remote/ref/签名 reviewer**，commit 没有混淆或无审查的替换，path 白名单合法且不泄漏秘密；检查 Git/Python 原始二进制和依赖。
- 真正独立机器复核：从独立已认证 Git clone 重新构建相同 TAR，在另一台主机比对 SHA256、commit/tree/blob ID 以及完整内容；复制批准白名单和签名票据需符合企业权限与 TTL。
- 宿主联动：在已获授权的 nonroot Podman/systemd/cgroup-v2 主机上以 EC253/257 同一 source.tar/policy/双票据运行固定 profile；对 runtime TAR 在 `begin/poll/reap` 中的篡改、权限撤销、重启和副本失配做拒绝与全树回收检查。
- 异常与可信计算：故意替换 Git object/修改 allowlist/使文件超限，证实无覆盖、无假 PASS、无宿主裸跑；做对象库竞态、NFS/共享存储、其他 UID/管理员权限测试。**当前仅在 Linux 非 root 本地真实 Git 上完成功能检查**；没有真实 remote-origin 审计和线上 OCI 复核。
- 原 PowerShell7 15 Smoke、Windows/macOS、E63–E66、Enterprise/Provider/CI、Router 11 `HOST_REQUIRED`、外部业务写/Cycle 及最终集成验收累计保留 `NOT_RUN`。

## 实际本地开发用例

```sh
# 在可以访问工程的 non-root Linux UID 下：
python3 -B construction/ec258_git_tar_custody/test_custody.py -q
```

EC258 25 项覆盖**真实 Git commit/tree/blob**、dirty worktree 排除、确定性 TAR/EC252 解包、SHA1/SHA256 Git 格式、tar/receipt/allowlist 篡改、文件白名单、symlink、repo owner/alternate/无覆盖、原 EC253 两签名有效绑定和错误 MAC/来源 SHA 的拒绝。该数量和旧 EC252–257 mock OCI/cgroup 测试不能替代 final acceptance。
