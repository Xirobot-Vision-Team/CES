# EC-253：Linux EC186 双签名一次性 Lease + 可恢复 QualityRun 宿主

**版本 V5.63/R253；一个用户授权的 EC253。** 实现位于 [`construction/lease_host/broker.py`](../construction/lease_host/broker.py)，复用 EC252 已有的 rootless Podman 固定配方。此入口独立于原始 74 条 Router 路由，**不会**将 11 个 `HOST_REQUIRED` 入口自动启用；EC186/187 原源码、Native PowerShell、旧 Smoke 均未改。**不是 EC187 `begin/poll/stop_and_reap` 协议实现，也不是 CI 或内核隔离独立认证**。

## 新增真实功能

- 从 **AF_UNIX/SO_PEERCRED 的 kernel UID** 取身份，匹配仅宿主能够设置的 `uid + scope_id + profile_ids`。客户端严格只传 `schema/scope_id/profile_id`；**不能**传令牌、TAR、命令、镜像、测试参数、执行资源上限、输出授权或终止信号。
- 宿主私有 `0600` 文件保存**两把互不相同**的 EC186 HMAC 密钥（approval/policy 和 isolation/broker），以及按原 `DOMAIN_APPROVAL` / `DOMAIN_LEASE` 签发的 EC186 ticket JSON。通过 EC186 **原有签名校验函数**验证全部签名字段、时间窗口、源码 pin、固定 profile 的代码内 SHA、用途、批准 receipt SHA、固定 OCI image SHA 和完整 `REQUIRED_CONTROLS` 声明。批准或 lease 任何字段改动即拒绝；执行期间按 EC252 控制循环重新核对策略、密钥、ticket 和有效期。
- 仅在 EC252 实际安全 staging、运行时/image 本地自检完成后，**在尝试 `podman create` 之前**按 `lease.ticket_id` 的域分离 SHA 文件名创建只允许一次的宿主私有 `0600` journal（`O_EXCL` + `fsync` 文件及目录）。持久占用一旦发生，即使容器没有启动/中途取消，也**不释放、不回滚、不允许重放**。把单次随机容器名、stage 目录、策略 SHA、TAR SHA、lease receipt SHA 持久记为 `reserved`，只追加 `closed` / `cleanup_uncertain` / `watchdog_cleaned` / `recovered` 生命周期事件。
- **单独 fork 出持有同一服务 leader lock 的短生命周期 watchdog**。Broker 被单独 `SIGKILL` 或超过固定 deadline，watchdog 尝试按预登记随机容器名运行固定 pinned Podman `rm --force` / `container exists`；确认容器不存在后才恢复 0555 staging 权限并删一次性 stage。正常清理也要求容器消失确认，写入 `closed`。新进程启动时取得独占 flock 后，**在接受任何新请求前**扫描全部旧 journal、尝试回收残留容器和私有 stage；任何不可确认回收、损坏日志、政策不匹配都阻断启动，须宿主人工处理，绝不宣布成功或自动重新执行。
- 检查结束仅能返回 `partial/2` 的**本地自报容器退出 0/非 0**，包含两份已验证 ticket 的 receipt 摘要、operator 声明的 source pin、已消费 lease 标识与 stdout/stderr SHA。**不得**提升为原始 repo 内容被证明、企业授权已认证、内核隔离已独立验收、CI PASS 或完整功能完成。无 Podman 时返回 `unavailable/5`，并且**不会消耗 lease**（因为此时尚未开始创建容器）。

## 可信边界和必备条件

1. 与 EC252 相同，准备**独立非 root Linux 服务账户**、可运行 rootless Podman + 本地预装 immutable image、owner-only `private/scratch/socket/ledger/home/XDG_RUNTIME_DIR`。将 `ledger_root` 放在**仓库之外**的专用 0700 目录，不得与 scratch、home、source 或 ticket/key 路径嵌套。Podman 必须 root-owned、单硬链接、不可其他用户改写、SHA 固定；**容器运行代码必须是来自宿主审查、去凭据的不可变私有 TAR**，不要把用户仓现有环境变量或 secrets 给容器。
2. 宿主 operator **必须在信任域之外独立核验**批准者实际授权与源 TAR 采集过程。`authorized_source_pin_sha256` 是 operator 对真实 EC181 WorkingTree pin 与 TAR 内容对应关系的**声明**，本代码只验证声明与原 HMAC ticket 内 pin **一致**，并验证 TAR 文件 SHA；**不会重走真实 repo 的 EC181 root probe 或认证 Git commit、完整源码内容相等**。签名票据中 `controls.seccomp_enforced=true` 等只是已签**声明**，不是本代码获得 Linux 内核证明：真实 OCI seccomp/cgroup/network/filesystem/namespace 需最终验收。
3. 两把原始密钥**必须不同、每把不少于 32 bytes**，由独立可信签发端产生并在权限受控的 `0600` 文件中 provision。生产不可从样例或源码推导随机密钥，不能放进 CES 包/业务仓。签发方按 EC186 原有 `_canonical` 及 `hmac.new(key, DOMAIN_APPROVAL|DOMAIN_LEASE + canonical(unsigned_body), sha256)` 计算各自 `mac_sha256`。approval 和 lease 都必须是 EC186 **原格式**，不是新自定义可绕过 ticket；`lease.approval_receipt_sha256` 是 `guard._digest(guard.DOMAIN_RECEIPT, approval_ticket_full_object)`，`lease.image_sha256` 是镜像 ID 去掉 `sha256:` 前缀后的小写 64 hex。
4. 申请时钟需精确，EC186 的 `MAX_APPROVAL_AGE=300s`、`MAX_LEASE_AGE=60s`、相应最大有效期 600s/120s 以及约 30s clock skew 均生效；**签发和实际启动应紧邻**。运行中授权/签名失效即取消执行并回收；拒绝自动换密钥或擅自延长 lease。
5. journal 是**安全关键不可清理的一次性消费历史**：不要删除/修改 `lease-*.jsonl`、重新使用已消费 lease ID 或在不同 ledger 目录重复签发同一个 ticket。宿主应有专门的持久本地卷、备份、上限管理与 crash/reboot 操作手册。`MAX_LEDGERS=4096` 达到后拒绝新消费，而不是自动重放/删除历史；不能使用不具备预期 `flock/fsync/O_EXCL` 本地一致性的 NFS/共享网络存储。
6. watchdog 是**子进程级 best effort**：单独服务进程崩溃或超时时执行独立清理；**整组 systemd cgroup 被杀、OOM 导致 watcher 同时死亡、断电、宿主崩溃时不能即时清理**，下一次服务启动前的 recover 才能处理。生产应另设独立 systemd / 宿主级监督；若回收无法确认，要人工核对 `ces-ec252-*` 和 `scratch/ec252-*`，**不启动新执行**。EC253 代码要求单线程入口 fork；不要从多线程应用嵌入执行路径。

## 完整 operator 策略示例（所有 `<...>` 值是占位符）

文件必须由宿主进程账户拥有的私有目录中的 0600 regular file 提供，**不能放到本 Skill 工程目录内**。保留 EC252 所有原字段，在新的 EC253 schema 中增加 6 项：

```json
{
  "schema": "ces.ec253.quality_run_lease_host_policy.v1",
  "source_tar_path": "/srv/ces-host/private/source.tar",
  "expected_source_tar_sha256": "<SHA256 of exact approved TAR bytes>",
  "scratch_root": "/srv/ces-host/scratch",
  "runtime_path": "/usr/bin/podman",
  "expected_runtime_sha256": "<SHA256 of root-owned Podman executable>",
  "runtime_home": "/srv/ces-host/home",
  "runtime_xdg_dir": "/run/user/<service-uid>",
  "image_id": "sha256:<64 lowercase hex local Podman image ID>",
  "expected_ec186_catalog_sha256": "<guard.catalog_entry('python.pytest')['catalog_sha256']>",
  "grants": [
    {"uid": 1001, "scope_id": "quality-review",
     "profile_ids": ["python.pytest", "python.ruff"],
     "allow_output_text": false}
  ],
  "authorized_source_pin_sha256": "<SHA256 of EC181 WorkingTree pin in both EC186 tickets>",
  "approval_ticket_path": "/srv/ces-host/private/approval.json",
  "isolation_ticket_path": "/srv/ces-host/private/lease.json",
  "approval_hmac_key_path": "/srv/ces-host/private/policy.key",
  "broker_hmac_key_path": "/srv/ces-host/private/broker.key",
  "ledger_root": "/srv/ces-host/ledger"
}
```

`profile_ids` 要严格**排序、去重**；审批 ticket 只会批准某一个精确 profile，其他 profile 即使 grant 列出也不能凭同一张 ticket 执行。所有路径必须绝对、无 `..` 或 symlink 祖先，文件 owner-only；`runtime_path` 须满足 EC252 的 root-owned SHA pin。

## Client 请求、服务及恢复

用户请求严格三字段，不能携带任何 signed ticket 或 token：

```json
{"schema":"ces.ec253.quality_run_lease_host_request.v1","scope_id":"quality-review","profile_id":"python.pytest"}
```

```sh
# 经宿主可信操作员离线配置好 private/ledger/TAR/keys/tickets/OCI 后：
python3 -I -B construction/lease_host/broker.py serve \
  --policy /srv/ces-host/private/policy.json \
  --socket /srv/ces-host/socket/run.sock --max-requests 1

# 客户端也验证 socket 对端是具体的、预期的服务账户 UID：
python3 -I -B construction/lease_host/broker.py request \
  --socket /srv/ces-host/socket/run.sock \
  --request-file /path/to/scope-profile-request.json \
  --expect-host-uid 1102

# 发生异常清理时，由宿主操作员在相同非 root 专用服务账号下恢复：
python3 -I -B construction/lease_host/broker.py recover \
  --policy /srv/ces-host/private/policy.json
```

调用返回码：`partial=2` 表示**本地 OCI exit 结果待独立验证**；`permission_denied=3` 包括重放；`invalid_input=4` 表示错误请求；`unavailable=5` 表示安全边界、签名、运行时、生命周期或恢复无法确认。`recover` 不能修复断电后改变策略 SHA、损坏 journaling、丢失 Podman 的事故，只会拒绝并要求人工处理。不能为了“通过测试”把 `seccomp`/签名/回收检查关掉。

## 本轮局部结果与联合验收积压

- 已运行 **20/20** 个 EC253 非 root Linux 开发测试：真实私有策略/密钥/源 TAR、AF_UNIX 对端 UID、实际隔离子进程 fork watchdog 的限时回收、O_EXCL 持久 lease 重放拒绝、跨进程重启恢复、吊销时 fail-closed、**mock Podman** 生命周期以及清理不确定的停止；**没有真实 OCI 镜像执行**。
- 继承 **EC252 24/24** 本地开发回归，确保前轮可直接运行的无签名独立入口未变；EC252 的 `_run_container` 仅新增一对**可选**生命周期回调，外部旧 API 和响应 shape 均保留。
- **待用户辅助统一验收：** rootless Podman 真实 create/start/inspect/kill/recovery、完整 seccomp/cgroup / bind mount / network / namespace 独立检查、断电与 systemd cgroup 同杀、管理员换 key 或策略、不同真实 UID、HMAC 发行系统、EC181 WorkingTree 到 TAR 独立内容封存、EC187 真实 `begin/poll/stop_and_reap` broker 适配、CI/Git/Provider 身份、R150/PowerShell7 及原 15 Smoke、E63–E66、Windows/macOS、原最终全功能与用户批准的验收。**B001 OPEN，原 EC249 FULL_FUNCTION_NOT_COMPLETE、原 EC250 冻结 BLOCKED，均未解除。**
