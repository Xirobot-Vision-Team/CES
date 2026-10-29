# EC333 无签可交接差异原件：独立 whole SHA + EC332 全链原签字节重构契约

## 单一新原件格式与权限

`ces.ec333.replayable_unsigned_two_set_delta_handoff_original.v1`，canonical sorted-ASCII LF JSON（末尾 `\n`），最大 **320,000 bytes**，本地 `0600` 单硬链接常规文件；候选生成 `O_EXCL`、`O_NOFOLLOW`、`fsync` 文件和父目录，绝不覆盖任何已有原件。保留完整字段：

| 字段 | 精确限制 |
|---|---|
| `schema` | 固定 `ces.ec333.replayable_unsigned_two_set_delta_handoff_original.v1` |
| `interpretation` | 固定 `unsigned_offline_finite_local_observation_only_requires_independent_whole_original_sha_and_replay_of_all_prior_signed_sources` |
| `left_manifest_original_raw_sha256`、`right_manifest_original_raw_sha256` | 双方**调用者独立提供的** manifest whole raw SHA 声明；不含路径，不自行创建 trusted anchor |
| `recomputed_ec332_local_delta` | 原生产 `delta.compare` 真重放两次 EC331→EC294 后得到的**全部** EC332 离线未决 JSON；不能从旧 stdout、缓存或 handoff 伪造 |
| `offline_unresolved_exit_code` | `2`，始终本地有限未决 |
| 固定 22 个继承+新增安全否定字段（`FALSE_FIELDS`） | **只能全部 false**；包括所有 actual remote/WORM/CAS、组织真实授权、signed handoff、独立 SHA 自证、全球历史/latest、签名远端非执行和路径迁移即验的非事实 |

原文件**不嵌入自身 SHA**（避免循环自引用）；`create-handoff` 的结果返回本地候选 whole SHA 和长度。接收者须从新独立可信渠道锚定这一 SHA；不能复制候选 stdout 中的计算结果充当独立受信证明。

## 各阶段可调用入口

```
python3 -I -B scripts/ces_cas_report_set_handoff.py create-handoff \
  --out /absolute/private/unique-original.json \
  --left-manifest-file /absolute/private/left.json \
  --left-expected-manifest-sha256 <left-sha-from-separate-channel> \
  --right-manifest-file /absolute/private/right.json \
  --right-expected-manifest-sha256 <right-sha-from-separate-channel>

python3 -I -B scripts/ces_cas_report_set_handoff.py verify-handoff \
  --handoff-file /absolute/private/unique-original.json \
  --expected-handoff-sha256 <third-sha-from-separate-channel> \
  --left-manifest-file /absolute/private/left.json \
  --left-expected-manifest-sha256 <left-sha-from-separate-channel> \
  --right-manifest-file /absolute/private/right.json \
  --right-expected-manifest-sha256 <right-sha-from-separate-channel>

python3 scripts/ces_next.py audit-hold-report-set-handoff \
  DeliveryAudit VerifyPinnedReportSetDeltaHandoff \
  --handoff-file /absolute/private/unique-original.json \
  --expected-handoff-sha256 <third-sha-from-separate-channel> \
  --left-manifest-file /absolute/private/left.json \
  --left-expected-manifest-sha256 <left-sha-from-separate-channel> \
  --right-manifest-file /absolute/private/right.json \
  --right-expected-manifest-sha256 <right-sha-from-separate-channel>
```

`create-handoff` **仅独立 standalone**；统一 CLI 只有固定 `-I -B verify-handoff` 只读调用，不暴露 `--out`、signer、private key、网络、Provider、外部 CAS 写入。成功核验返回 schema `ces.ec333.offline_delta_handoff_result.v1`，`status=unsigned_offline_delta_handoff_exactly_reconstructed_unresolved`, exit2；创建方 status `...candidate_created_unresolved` 也 exit2，但其 `handoff_original_exactly_reconstructed_from_both_original_signed_histories=false`。拒绝 schema `ces.ec333.offline_delta_handoff_denial.v1`，`3=permission_denied`、`4=invalid_input`、`5=unavailable`。绝无 exit0 remote success。

## 全历史信任流（禁止偷换）

1. 输入包括**两个不同私有规范 EC331 manifest 文件路径**，各自 2–8 份 EC330 报告及每报告旧签全受信源码字段，每份独立 entrusted whole SHA；`--out`/`--handoff-file` 路径不允许等于已知的 manifest、原报告、当前/上一个 EC328 ledger、其中 ninth 签名原件或嵌套明确来源路径；不认可硬链接多链接文件。
2. 先通过实际生产 `ec332_pinned_report_set_delta.delta.compare` 完整回放两份 manifest：每份生产 EC331 和每个 EC330 真重构；其下生产 EC329、EC328、EC327、EC326、EC325→EC294 全部原有独立 signed 原历史需要满足。旧模拟 fixture 不能通过真正的隔离进程。
3. EC332 的保守本地 SHA 去重、左独/右独/共见、已验直接 parent、同父双分叉、角色重复披露**不增加“签名票数”**、不推出时序/全球权威。两个 manifest、所有旧源/前 ledger/真 ninth receipt 已在 EC332 内末尾 re-pin。
4. 完整 EC332 结果和两 manifest whole SHA 一起做 canonical handoff 原字节。创建前后追加全部源、报告、manifest whole SHA 读回；写入后重新读取 handoff 原 SHA。若读写期间变化，绝不宣称可信候选。不能推出任意时刻原子 file-system snapshot 或 ABA 防护。
5. 接收者**必须另外** trusted handoff 原 SHA，以及**另外** trusted 两 manifest 原 SHA 和其完整旧签名材料。对 handoff 原件先校验 0600、单硬链接、规范整原文件、exact schema/keyset、双方外部 pins、无签未决 flags；再运行上述完整生产 `delta.compare`，要求整个 JSON **严格相等且 raw bytes 完全相同**，最后再读双侧旧 signed originals/报告/manifest 和 handoff 原 whole SHA。
6. 任何一侧文件改动、源签名无效、报告无法重建、权限错误、候选文件篡改或子程序声称远端成功都整体拒绝。无法完成真实历史回放时不能降级为 `sha256sum` 比对或旧缓存相等。

## 接收机器的实际条件 / 精确限制

handoff 文件可以单独复制，但**不具有脱离原料自证的可验证性**。原 EC331 manifest 内固定绝对路径；独立接收者必须在自己的环境能在**对应路径**取回独立原 SHA 固定的原文件与签名；任意重写 manifest 内路径都会改变其原 SHA，不是本协议支持的“透明路径迁移”。EC332 的本地回执路径复用指纹可能随本地路径差异变化，故整个 raw handoff byte-exact 检查会拒绝路径漂移。若未来需要异构主机路径重绑定，应在后续单独 EC 中以已有 EC317/318 绑定原协议设计，不得把这一项误写成已经支持。

## 实际测试事实（本轮）

`PYTHONPATH=construction:. python3 -B -m unittest construction.ec333_replayable_delta_handoff.test_handoff -q` => **15/15 PASS**。本地第八/九 Ed25519 真签（结构 fixture），旧 EC317/318 深层签名 MOCK；真 `-I -B` 子进程对此 fixture 预期 exit4，不是全部旧生产原签历史通过。实际外部机构、物理独立 SHA custody、远端 CAS/WORM/真实 nonexecution/readback、global latest/winner、原 PS7 Smoke15/跨 OS/真实业务/用户最终验收均未证明。EC249 incomplete、EC250 BLOCKED、B001 OPEN、Quality PASS=false、final NOT_STARTED 不变。
