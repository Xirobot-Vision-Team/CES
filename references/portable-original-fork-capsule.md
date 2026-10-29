# EC323 双原件离线便携封存与独立全链复验协议

## 目标、信任源与责任边界

EC321 的完整真签分叉案卷是一个**原字节 ZIP**，EC322 的第七独立接收方确认是**原字节、Ed25519 真签 LF JSON ACK**。EC323 **不会重签、修改或重新序列化这两份原件**，只在运行原 EC322 `verify` 并成功得到真分叉 `exit=2` 后，生成一份能移动到另一台机器的 `ZIP_STORED` 规范离线便携封装。该封装**不是**另一份签名、不是第八身份、不是额外权限或真实远端 WORM/CAS 存证。

**接收端必须拥有预先通过 ZIP 以外的可信渠道固定的完整信任参数**：

1. `expected-capsule-sha256`：本 EC323 生成的**整份封装二进制文件** SHA-256，必须在封装产生之后从独立渠道获取；
2. `expected-bundle-sha256`：EC321 案卷原 ZIP 整份 SHA-256；
3. `expected-ack-sha256`：EC322 七方 ACK 原 JSON 整份 SHA-256；
4. EC321 的全部 12 个原外部 pins：`case-id`、`witness-id`、`witness-public-hex`、`witness-challenge-sha256`、`expected-witness-sha256`、`expected-left-sha256`、`expected-right-sha256`、`expected-left-head-raw-sha256`、`expected-right-head-raw-sha256`、`expected-genesis-raw-sha256`、`registrar-id`、`registrar-public-hex`；
5. EC322 七方独立角色四件：`ack-id`、`seventh-receiver-id`、`seventh-receiver-public-hex`、`seventh-receiver-challenge-sha256`。

注意：封装自带的 manifest 虽为规范 JSON，却**是未签传输元数据**；只用于核对，**不能**从其中自取信任公钥或 pins。即使整份 ZIP SHA 正确，也不能替代七方签名及历史原签重放，不能证明另一设备、法人授权、真实在线交付、WORM/CAS 的不可回滚最新状态或分叉胜者。

## 精确封装格式与安全边界

封装是字节级确定性的标准 `ZIP_STORED`，仅有以下**三个条目，顺序固定**：

| 条目 | 内容 | 限额 |
| --- | --- | --- |
| `capsule-manifest.json` | 规范 LF JSON，含全部外部 pins、七方角色、两原件名称/大小/SHA、明确 `global_latest_fork_winner_or_external_cas_proven=false` | ≤ 16,000 字节 |
| `original-case.zip` | 未变更的 EC321 整份原 ZIP | ≤ 128,000,000 字节 |
| `original-seventh-ack.json` | 未变更的 EC322 原七方签名 ACK | ≤ 20,000 字节 |

封装总大小 ≤ 128,044,192 字节。条目固定 epoch 时间戳、Unix `0600` regular-file 类型、无注释、无附加字段、不压缩、不使用外部条目名做提取路径。验证会校验**完整封装整字节 SHA、条目数/名字/顺序/类型/大小、内部两份原 SHA、清单规范性、整个 ZIP 与规范构造字节完全一致**。拒绝外加条目、相对路径穿越、重复中央目录名、压缩炸弹、存档前/尾杂字节及重算外 ZIP SHA 后偷偷替换某一原件的情况。

只支持项目既定的 POSIX 形式绝对路径与 owner-private 目录/文件语义：输入需受限的 `0600` 单硬链接常规文件，父目录 owner-only（典型 `0700`），输出 `O_EXCL`、`0600`、fsync 文件与父目录，不覆盖；Windows/macOS 的等价权限和双设备迁移应在后续用户验收实测。验证过程中，只把两原件写入新建的 `0700` 临时目录中**受程序控制的固定文件名**，且自动清除；无业务 Host/CAS 写，不向原 EC321/322 文件系统取文件，不会自动根据 manifest 中历史路径取源。

旧 EC317/318 签名记录中可能包含原机器绝对路径字符串；**本封装不负责脱敏或加密原签字节**，线下介质分级/加密应由外部组织制度另行处理。

## 1. 在拥有两份已签原件的机器上 seal（不需要任何私钥）

前提：既有 EC321 ZIP 与 EC322 ACK 均已受信固定整份 SHA；所有身份和旧源 SHA 经可信**包外**渠道给出。要求两份旧源是私有常规文件，`--out` 位于 owner-only 目录下，**尚未存在**。`seal` 首先实际执行 EC322 的 `verify`：校验七方 Ed25519，重验 EC321→EC320→EC319→EC318→EC317→EC294 两支真签全原件；全部通过后才装入两个原始字节文件。

```bash
python3 scripts/ces_cas_fork_capsule.py seal \
  --bundle-file /private/source/ec321-original-case.zip \
  --expected-bundle-sha256 <EC321_WHOLE_RAW_SHA> \
  --ack-file /private/source/ec322-seventh-ack.json \
  --expected-ack-sha256 <EC322_ACK_WHOLE_RAW_SHA> \
  --ack-id receipt_case_322 \
  --seventh-receiver-id independent_receiver_seven \
  --seventh-receiver-public-hex <SEVENTH_PUB_HEX> \
  --seventh-receiver-challenge-sha256 <SEVENTH_CHALLENGE_SHA> \
  --case-id <EC321_CASE_ID> \
  --witness-id <SIXTH_ID> --witness-public-hex <SIXTH_PUB_HEX> \
  --witness-challenge-sha256 <SIXTH_CHALLENGE_SHA> \
  --expected-witness-sha256 <SIXTH_WITNESS_ORIGINAL_SHA> \
  --expected-left-sha256 <LEFT_REGISTRY_ORIGINAL_SHA> \
  --expected-right-sha256 <RIGHT_REGISTRY_ORIGINAL_SHA> \
  --expected-left-head-raw-sha256 <LEFT_SIGNED_HEAD_RAW_SHA> \
  --expected-right-head-raw-sha256 <RIGHT_SIGNED_HEAD_RAW_SHA> \
  --expected-genesis-raw-sha256 <SIGNED_GENESIS_RAW_SHA> \
  --registrar-id <REGISTRAR_ID> \
  --registrar-public-hex <REGISTRAR_PUB_HEX> \
  --out /private/out/ec323-original-case-plus-ack.zip
```

成功返回 `status=authentic_original_case_and_seventh_ack_sealed_without_resigning`、`exit_code=2`、`capsule_original_raw_sha256`；**外部受信渠道务必记下新封装 SHA**。不能因不是零退出码而将这次真分叉记录认作失败，也不能因为存在封装便声称完成了外部交付。

## 2. 仅携带封装和包外信任，在另一机器上 verify

这一步不需要任何 `bundle-file`、`ack-file`、私钥、原 EC319 映射文件或签署源目录；从封装中在新临时目录分别原样恢复这两个文件。其余 18 个参数与第一步信任选择保持一致，额外提供**可信包外整份封装 SHA**：

```bash
python3 scripts/ces_cas_fork_capsule.py verify \
  --capsule-file /private/inbox/ec323-original-case-plus-ack.zip \
  --expected-capsule-sha256 <EC323_WHOLE_RAW_SHA> \
  --expected-bundle-sha256 <EC321_WHOLE_RAW_SHA> \
  --expected-ack-sha256 <EC322_ACK_WHOLE_RAW_SHA> \
  --ack-id receipt_case_322 \
  --seventh-receiver-id independent_receiver_seven \
  --seventh-receiver-public-hex <SEVENTH_PUB_HEX> \
  --seventh-receiver-challenge-sha256 <SEVENTH_CHALLENGE_SHA> \
  --case-id <EC321_CASE_ID> \
  --witness-id <SIXTH_ID> --witness-public-hex <SIXTH_PUB_HEX> \
  --witness-challenge-sha256 <SIXTH_CHALLENGE_SHA> \
  --expected-witness-sha256 <SIXTH_WITNESS_ORIGINAL_SHA> \
  --expected-left-sha256 <LEFT_REGISTRY_ORIGINAL_SHA> \
  --expected-right-sha256 <RIGHT_REGISTRY_ORIGINAL_SHA> \
  --expected-left-head-raw-sha256 <LEFT_SIGNED_HEAD_RAW_SHA> \
  --expected-right-head-raw-sha256 <RIGHT_SIGNED_HEAD_RAW_SHA> \
  --expected-genesis-raw-sha256 <SIGNED_GENESIS_RAW_SHA> \
  --registrar-id <REGISTRAR_ID> \
  --registrar-public-hex <REGISTRAR_PUB_HEX>
```

`status=independent_portable_original_case_seventh_ack_and_all_histories_reverified`、`exit_code=2` 才表示在给定包外信任下重新验出**仍未裁决的真实双支分叉**，并重新验证原七方签章与更早全部签章。3/4/5 都不应被接受。`capsule_original_raw_sha256`、`case_bundle_original_raw_sha256`、`signed_receiver_ack_original_raw_sha256` 三项必须与包外 SHA 相同。

统一控制台也是**固定单模式只读**：

```bash
python3 scripts/ces_next.py audit-fork-capsule \
  DeliveryAudit VerifyPortableOriginalForkCapsule \
  --capsule-file /private/inbox/ec323-original-case-plus-ack.zip \
  --expected-capsule-sha256 <EC323_WHOLE_RAW_SHA> \
  --expected-bundle-sha256 <EC321_WHOLE_RAW_SHA> \
  --expected-ack-sha256 <EC322_ACK_WHOLE_RAW_SHA> \
  --ack-id receipt_case_322 \
  --seventh-receiver-id independent_receiver_seven \
  --seventh-receiver-public-hex <SEVENTH_PUB_HEX> \
  --seventh-receiver-challenge-sha256 <SEVENTH_CHALLENGE_SHA> \
  --case-id <EC321_CASE_ID> \
  --witness-id <SIXTH_ID> --witness-public-hex <SIXTH_PUB_HEX> \
  --witness-challenge-sha256 <SIXTH_CHALLENGE_SHA> \
  --expected-witness-sha256 <SIXTH_WITNESS_ORIGINAL_SHA> \
  --expected-left-sha256 <LEFT_REGISTRY_ORIGINAL_SHA> \
  --expected-right-sha256 <RIGHT_REGISTRY_ORIGINAL_SHA> \
  --expected-left-head-raw-sha256 <LEFT_SIGNED_HEAD_RAW_SHA> \
  --expected-right-head-raw-sha256 <RIGHT_SIGNED_HEAD_RAW_SHA> \
  --expected-genesis-raw-sha256 <SIGNED_GENESIS_RAW_SHA> \
  --registrar-id <REGISTRAR_ID> \
  --registrar-public-hex <REGISTRAR_PUB_HEX>
```

统一入口使用固定 Python `-I -B` 子进程调用 `verify`；不接受 `seal`、`--out`、`--private-key-file`，不会绕过旧验签或触发远端 CAS/Host/Provider。

## 3. 已知未验项目（集中留给最终统一验收）

本轮 17 条 EC323 结构用例使用**真实第五/第六/第七 Ed25519 密钥与签名**，验证并比较两份原字节、自动销毁源文件后的迁移复验、坏签名和原旧链拒绝、重复条目、压缩/穿越、非规范数据、源替换与只读入口边界。**EC317/318 的深链在继承的 EC321 轻量 fixture 中明确使用 mock**，所以不是原 EC294→323 完整生产签章联调的替代证明。

仍要由用户最后统一完成真实全量原证据链验签、两物理机器/机构授权与可信受信渠道、权限模型和跨平台、外部不可回滚托管/CAS/WORM、旧 PowerShell7/15 Smoke、生产 Provider/Inbox/Git/CI/E63–E66 与最终联合验收。保留 EC249 incomplete、EC250 blocked、B001 open、global Quality PASS=false 与 final NOT_STARTED。
