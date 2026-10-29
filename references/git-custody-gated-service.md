# EC259 — 操作员使用 Git Custody Gated Strict QualityRun Host

## 作用与边界

EC259 以**新独立入口**强制把 EC258 本地 Git commit→TAR 内容保管和原 EC253 双签名授权纳入 EC257 严格 OCI 会话的服务启动/每次 `begin`。这是明确 opt-in 的本地宿主软件，不是 Client 或 Router 新 Action。既没有验证外部 Git 来源/真实提交审查者，也没有在施工环境运行生产 Podman、kernel cgroup-v2；所有“通过”只代表局部代码功能，不能变为 overall PASS。

运行主体始终是本地 **非 root、可信操作员 UID**；可信 Git/Python/Podman 发行、真实 systemd delegated cgroup、仓库来源认证及签名票据的外部授权由宿主操作员保证。同一个 UID 有权替换自己授权的 Git 文件、policy 或 receipt，因此必须将其视为**可信受控身份**；root/UID/持久存储遭入侵不能由这一本地哈希链挡住。

## 准备流程

1. 按 [EC258 手册](git-source-tar-custody.md)在 operator 自有 `0700` checkout 中确认完整（40/64hex）Git commit OID、审核严格升序的文件 allowlist（独立 `0600` JSON），用 `custody.py prepare` 生成未压缩 Source TAR + `source.custody.json`，**只读取真实 Git object，不使用 working tree**。
2. 由经授权的另一条流程单独准备好原 EC253 的私有 policy、EC186 `authorized_source_pin_sha256`、两张真正有效的不同密钥 MAC 票据、固定 image ID/可信 runtime，以及原 EC257 已要求的 Podman/systemd/cgroup-v2 系统能力。policy 里的 `source_tar_path` 必须**精确等于**上述 `source.tar` 绝对路径，`expected_source_tar_sha256` 必须等于 `custody.py prepare` 输出；两张票据必须针对 **相同的单个 EC186 固定 profile**，不能从 Git OID 自行推断 source-pin。
3. 只在**目标宿主允许真实执行**时启动 `serve`；先用 `probe` 做无副作用的源码票据校验。所有路径必须是当前 UID 自有/私有、不可经符号链接的绝对安全路径；不放入 CES 工程 ZIP。只有操作员 CLI 选择路径/固定 profile，客户端会话不能修改。

```sh
# 预检：返回 partial/2，不说明 Podman/cgroup 宿主已正确配置。
python3 -I -B construction/custody_gated_host/serve.py probe \
  --policy /srv/operator/approval/ec253-policy.json \
  --repo /srv/operator/private/git-checkout \
  --allowlist /srv/operator/approval/selected-files.json \
  --receipt /srv/operator/private/source-export/source.custody.json \
  --profile-id python.pytest

# 只有可信 Linux rootless Podman + systemd delegated cgroup-v2 宿主才启动：
python3 -I -B construction/custody_gated_host/serve.py serve \
  --policy /srv/operator/approval/ec253-policy.json \
  --repo /srv/operator/private/git-checkout \
  --allowlist /srv/operator/approval/selected-files.json \
  --receipt /srv/operator/private/source-export/source.custody.json \
  --profile-id python.pytest \
  --socket /srv/operator/private/sockets/ces-ec259.sock \
  --max-sessions 1 --accept-timeout 60
```

服务使用原 EC254 `TrustedBroker`/EC187 会话协议；仍要求原签名 scope、当前 UID、Lease、deadline 与固定预算参数，无“关闭 custody/cgroup/内核计量”请求字段。`probe` 失败返回 5，严格服务启动失败/本地配置失效同样 fail closed。成功 `probe` 输出 `status=partial, exit_code=2` 与 `strict_ec257_host_live_verified=false`；服务成功退出返回 0 仅表示完成了本次监听周期，**不表示任何质量 PASS**。

## 启动与每次执行顺序

```text
serve entry (operator private CLI)
  → EC253 durable ledger orphan recovery (uncertain => fail closed)
  → EC257 delegate mount/boot prerequisites
  → original EC253 policy read + hash
  → EC259 startup: real Git objects + allowlist → exact TAR + receipt
  → EC253 source_tar_path/SHA + TWO original signed MAC tickets
  → pin policy bytes SHA for lifetime of this service
  → original EC252 source TAR hash / private host dirs
  → original EC253 durable lease recovery → private AF_UNIX socket bind
  → peer UID and signed scope/profile/lease/deadline check
  → EC259 per-begin: same profile + unchanged policy + Git/TAR/receipt/tickets
  → untouched source TAR hash read → worker fork → durable one-use lease
  → EC257 cgroup-bind/metric/final pre-reap + EC256 whole-group reap
  → host-only partial response or fail closed
```

如果 startup 不通过，**不创建监听 socket**；如果已经启动后批准路径、Git 内容证明、receipt、TAR 或签名改变，下一次 `begin` 在 **worker fork/Lease consume 之前**被拒绝，不应产生业务 Podman 容器。已经进入运行状态的容器依赖原 EC253/256/257 worker watchdog、内核回收及策略重新检查；EC259 **不提供运行中无限次远端 Git 证书复查或实时撤销**。

## 出错与运营方式

- `EC259_CUSTODY_*`：EC258 本地对象/白名单/TAR/receipt 的已存在失败码；或原 EC253 policy/票据绑定不足。不要覆盖原 TAR/receipt 继续重试。先审核源和权限，再依据授权流程重新制作整对输出，并签发相应新 policy/tickets。
- `EC259_UNAPPROVED_PROFILE`：客户端选了非本次操作员固定的 profile；拒绝跨 profile 复用。
- `EC259_POLICY_PIN_CHANGED` / `EC259_POLICY_RACED`：策略版本改变/复核间竞态；关闭当前入口，独立审核后再启新服务；不能用随机重签绕过本次拒绝。
- `EC259_PRESTART_RECOVERY_UNCERTAIN`：先处理旧 EC253 Lease/残留 OCI，不得因为新版源码未通过而跳过清理。
- 新入口除了原 EC254/257 已有的限时、非 root、SO_PEERCRED/owner-private Socket、HMAC Lease、kernel source、全树回收限制，**没有新增外部网络请求或仓库写入**。部署时不得将私有票据、Git repo、策略文件或 receipt 放入 ZIP。

## 目标宿主集中验收（本环境未运行）

- 真正被认证的远端 Git repo/commit 签名/审查者身份与相同 commit 的独立 clone/TAR 字节哈希复核；证明 EC186 源 pin 的实际授权来源。
- 在实际 `podman` rootless + systemd cgroup2 delegate 上用真实 Source TAR、签名票据、scope、镜像运行 `begin/poll/stop_and_reap`，检查真正 `cpu.stat/memory.peak/pids.peak/io.stat`、`cgroup.kill` 和多 PID 全树清理。
- 运行中与运行前撤销/篡改 policy、allowlist、receipt/TAR、Git OID、MAC key；断电/SIGKILL/restart/Lease 重放、路径 inode 替换、无源/不可读、同 UID 协作管理员变化、多 UID 权限隔离。
- 原 15 PowerShell Smoke、E63–E66、原 11 Router `HOST_REQUIRED`、企业 CI/Provider/Issue/Delivery/Cycle 与最终用户辅助完整验收仍为 `NOT_RUN`。

## 本地聚焦测试

```sh
# 使用非root Linux + /usr/bin/git，建议 umask 077；这些测试模拟 Podman/cgroup：
python3 -B construction/custody_gated_host/test_gate.py -q
python3 -B construction/custody_gated_host/test_host.py -q
```

新增 15 个 Gate/本地真 Git/签名/篡改用例和 4 个真 Unix fork/签名 Lease/模拟 OCI/cgroup 的链路用例已在施工环境执行；结果 **19/19 本地 PASS**，绝不能替代生产宿主验收。
