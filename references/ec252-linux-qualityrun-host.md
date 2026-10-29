# EC252 — Linux 单点授权、固定镜像 QualityRun 宿主执行器

**完整工程包 V5.62/R252/EC252。** 本轮新增独立的、显式 opt-in 的 Linux AF_UNIX 端点 `construction/ec252_quality_run_host/broker.py`。这是一个**可以在具备可信 rootless Podman 的宿主上真实启动容器**的执行器，不是只生成计划的桩；它仍不是 EC187 的签名 lease broker，也**没有接通**原来 74 条 Router 的 11 个 HOST_REQUIRED 模式。原生 CLI V4.60/R150、Router wire V5.53/R243 与 EC250/EC251 均保留。

## 功能边界 / 真实性

- 服务在**非 root 专用 Linux 账户**下运行；从 Linux `SO_PEERCRED` 获取客户端 **kernel UID**，匹配宿主拥有的 `uid + scope_id + profile_id` 白名单。client JSON **绝不**提供源码路径、镜像 ID、参数、执行文件、运行资源配额或输出权限。
- 源输入只能是操作员预先准备的 **0600、SHA256 精确固定、单硬链接、无符号链接的私有未压缩 TAR**，宿主独立持有；上限 16MiB、最多 2,048 项、解压 32MiB、单文件 8MiB；只接受纯 ASCII 的相对正规文件/目录路径，拒绝 TAR link、special files、`.git/.ssh/.aws/.env` 和路径穿越。将字节复制到本次新建的专用临时目录，生成只读文件和目录；**不执行源仓的脚本或宿主 shell**。
- 仅选择**现有 EC186 内置** `python.pytest` 和 `python.ruff` 配方，读取并核对 EC186 原始 catalog SHA；宿主必须预安装 Python `/usr/bin/python3`、`pytest`、`ruff` 的指定本地镜像 **image ID（sha256:...）**，绝不自动拉镜像或回退到宿主 Python。执行器二进制须为系统 root 拥有的不可组写/全局写单硬链接 regular file，以 `O_NOFOLLOW` dirfd 打开及 SHA256 固定。`podman info` 必须报告 `Host.Security.Rootless=true`，`podman image inspect` 必须返回完全一致的不可变镜像 ID。
- 使用 Podman `create → start --attach → inspect State → rm --force → container exists` 真实路径。`--read-only`、只读 `/workspace`、`--network=none`、`--userns=auto`、容器用户 `65534:65534`、独立 pid/ipc/cgroup ns、drop all caps、no-new-privileges、max 32 pids、256MiB 内存和 swap、1 CPU、CPU 40s 和单文件 64MiB ulimit、64MiB `/tmp`，本地附加过程 wall 60s 和总 stdout+stderr 12KiB。CLI 子进程被新进程组监督，超限/授权变化/客户端断开时终止 CLI 并随后按容器名字强制清理。**Podman 与 kernel 是否真正安装且强制执行这些隔离参数还必须宿主复核**，参数本身不是核级安全证明；无独立 crash watchdog、无法担保 SIGKILL/断电时不残留。
- 启动前、执行期间定期（约 0.4s）和返回前重复检查私有策略字节 SHA 和当前 UID scope 授权；源码 snapshot 在开始/结束时复核，容器总使用已复制的快照，不从可能变化的 Git 工作树直接读取。容器存在与否确认失败时**不会给出运行结果**，保留隔离临时目录以供宿主事故处置。即使引擎报告 exit 0 仍只返回 `partial/2`，`local_test_outcome=exit_zero`；**`overall_quality_pass_verified=false`**，也不声称源内容来自可信 Git commit、CI 已认证或组织成员身份已认证。
- 默认不向 client 泄露任何日志内容，只返回收集输出的 SHA256 与总字节数；宿主 grant 显式 `allow_output_text=true` 才返回最多每流 4096 字节的过滤文本，超 12KiB 是 fail-closed 而非被误称成功。此响应可包含测试代码打印的敏感内容，操作员须审查授权和素材。

## 上线前的宿主必要条件

1. **专用服务账户**（不得使用 root、也不要让不可信 client 与它共享同一 UID）。Linux 且支持 AF_UNIX/SO_PEERCRED、rootless Podman、user namespaces、可用 subuid/subgid、cgroup 和 OCI 隔离。`podman` 必须是固定 root-owned 非符号链接二进制；当前开发环境**没有** Podman，故本轮没有运行生产镜像。**没有 Podman、无法 rootless、任一强制参数不被支持时，应看到 `unavailable/5`，严禁改成非隔离的 host subprocess。**
2. 在 `ces/`、被分析原仓和任何共享目录**之外**准备三个仅由服务账户拥有的 0700 目录：`private`（政策和 snapshot TAR）、`scratch`（一次性 staging）、`socket`（AF_UNIX endpoint），及已配置的独立 0700 `HOME` 和 `XDG_RUNTIME_DIR`。`private` 内所有 JSON/TAR 都是 owner-only 0600 regular file；不能把策略放到仓库中。所有路径须正规绝对路径，无 symlink/`..`/可由其他用户修改的非 sticky 上级目录。当前脚本也拒绝配置在 CES 工程根内。
3. 操作员对**已经获准执行的源码**离线生成未压缩的只含代码和必要测试配置的、无凭据、无符号链接、无 `.git` 的 source TAR，单独计算实际 TAR 文件字节 SHA256。不要直接用 `tar -cf ... .`：它可能生成本模块拒绝的 `./` 条目，也可能夹带 `.env`/private files。建议从专门筛选后的干净导出目录生成 tar，并提前审查成员。**SHA 只证明文件字节一致，不证明 Git 来源、作者身份或依赖无恶意代码**。
4. 操作员从 **本地可信已预装镜像**中取得 `podman image inspect --format '{{.Id}}' <local-image>` 的 `sha256:...`；同时用 `sha256sum /usr/bin/podman` 获得本地执行器二进制哈希；依实际 `quality_run_guard.catalog_entry('python.pytest')['catalog_sha256']` 写入 catalog SHA。使用可信 provenance 流程审计 image、Python/pytest/ruff、OCI runtime、机器的 seccomp 与文件系统。这里不提供镜像构建或自动下载，避免无意执行未信任依赖。
5. socket 目录权限控制 + Linux UID 白名单必须同时成立。若要让其他 UID 访问 socket，操作员需另外安排限定的组权限/ACL；仅给到 socket 的写权限**不等于**通过 `uid+scope_id` grant。让一个 client 拥有与服务进程相同 UID，会损失 owner-only 策略的隔离边界。
6. 建议在实际部署时由 systemd 等外部监督系统提供服务 crash 时的 Podman 容器回收、隔离账户审计、政策撤销/轮换、日志目录配额和 host 升级审查；这些**不在 EC252 代码中自动安装**。如看到 `RUN_HOST_CONTAINER_OR_STAGE_CLEANUP_UNCONFIRMED`，宿主应暂停服务，用 Podman 自行核对名称 `ces-ec252-*` 的容器与未删除 `scratch/ec252-*`，而不是自动重新执行。

## operator policy — 所有 `<...>` 必须由宿主可信值填写

文件例子不代表已获准执行；`profile_ids` **有意按字典序排列且去重**，不得有额外字段：

```json
{
  "schema": "ces.ec252.quality_run_host_policy.v1",
  "source_tar_path": "/srv/ces-runner/private/source.tar",
  "expected_source_tar_sha256": "<64 lowercase hex: sha256sum source.tar>",
  "scratch_root": "/srv/ces-runner/scratch",
  "runtime_path": "/usr/bin/podman",
  "expected_runtime_sha256": "<64 lowercase hex: sha256sum /usr/bin/podman>",
  "runtime_home": "/srv/ces-runner/home",
  "runtime_xdg_dir": "/run/user/<service-uid>",
  "image_id": "sha256:<64 lowercase hex: local preinstalled image ID>",
  "expected_ec186_catalog_sha256": "<64 lowercase hex: actual EC186 catalog digest>",
  "grants": [
    {
      "uid": 1001,
      "scope_id": "quality-review",
      "profile_ids": ["python.pytest", "python.ruff"],
      "allow_output_text": false
    }
  ]
}
```

## 严格 client 请求

```json
{
  "schema": "ces.ec252.quality_run_host_request.v1",
  "scope_id": "quality-review",
  "profile_id": "python.pytest"
}
```

操作员启动服务（单次请求适合先验调试，按需启用更多请求；每个请求串行执行）：

```sh
python3 -I -B construction/ec252_quality_run_host/broker.py serve \
  --policy /srv/ces-runner/private/policy.json \
  --socket /srv/ces-runner/socket/run.sock --max-requests 1
```

客户端在拥有 socket 路径 OS 访问权限的情况下：

```sh
python3 -I -B construction/ec252_quality_run_host/broker.py request \
  --socket /srv/ces-runner/socket/run.sock \
  --request-file /path/to/request.json --expect-host-uid 1102
```

其中 `--expect-host-uid` 是**实际宿主服务 UID**，不应照抄示例。预期容器执行后返回 `partial/2` 和准确的 `local_test_outcome=exit_zero|nonzero`、源 TAR SHA、EC186 profile SHA、采集输出哈希；未执行或清理未确认返回 `permission_denied/3`、`invalid_input/4` 或 `unavailable/5`，绝不返回全局 PASS。所有响应都是请求作用域内的本地报告，不能直接当成 EC188 的已认证 CI evidence。

## 联合验收未完成事项

- **本轮实际本地：** 非 root Linux 下 24 个 focused 测试，包括真实 socket/`SO_PEERCRED`、0700/0600 私有文件、真 TAR 解包及限制、真实受限 Python 子进程取消/预算、**显式 mock Podman** 的 `create/start/inspect/cleanup` 控制流、policy revoke/OOM/权限拒绝。`python3 -B construction/ec252_quality_run_host/test_broker.py`（需非 root）可复跑。mock 只是控制流单元检查，不是生产容器。
- **待宿主：** 真正 rootless Podman image/profile 执行、OCI seccomp/cgroup、只读挂载和禁网复核、Docker/Podman 版本差异、cross UID/ACL 与管理员撤权、SIGKILL/崩溃/断电后独立回收、所有平台差异、CI/Git 来源证明。E63–E66、原 15 PowerShell7 Smoke、真实 provider/企业/外部 writes 和最终产品全链验收仍未运行；历史 B001 OPEN，EC249 的 `FULL_FUNCTION_NOT_COMPLETE` 不被改变。**原始 EC250 冻结候选仍 BLOCKED**。
