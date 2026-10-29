# EC325 — 包外双子头原签复验与本地未裁决争议案卷

## 目标、证据边界

EC324 的本地 SHA-linked 1–16 行收件快照是**单一可见分支**，不能防止并发收件者都从同一个已受信父头提交不同子头。EC325 增加一个**离线、本地、不会自动决议**的同父冲突检测协议。在双方完整证明各自为合法 EC324 子快照之前，不产生争议案卷。

真实使用时，至少要独立从可信**包外**渠道固定：

- 左、右 EC324 本地累积登记快照各自的**whole raw SHA256**，并且是两个不同 SHA；
- 左、右各自的 `origin` / `recipient` 未签 pin 文件整原 SHA（合计四个，不能把单一包内自述视为受信）；
- 左、右各自的 EC323 原便携封装 ZIP（ZIP 自身整 SHA 已由各自双 pin 中固定）；各个 pin 含原 EC321、EC322 整 SHA、EC321 12 个上游 pins 与 EC322 第七方四个受信参数；
- **同一个**独立受信 `registry_id`、`expected_sequence`、`expected_prior_registry_sha256`；若 `sequence >= 2`，还须父累积快照**原件**，由包外 SHA 钉住且不是两个子快照之一。

`sequence=1` 时父头只能是恰好 64 个 `0`，不得带父文件；`sequence=2..16` 必须带父原件，绝不能从任一子头自行推断父头 SHA 并予以背书。

## 真正的执行顺序

1. 严格检查所有路径：规范绝对路径、源侧内四文件不同、输出/案卷文件不可覆盖或冒充输入；检查每个必需的包外 SHA 类型和范围，左右子头不允许相同。
2. 分别对两个**整原 SHA 钉住**的 EC324 原快照运行原 EC324 前缀链、行结构、重复检测；两个末行必须不同，但完全相同的此前累积记录、同 `registry_id`、同 `sequence`。非 genesis 时要求该共享前缀逐字节复原的规范 SHA 与**独立父原件 SHA**完全相等，且前缀记录必须与实际收到的父快照内容完全一致。
3. 对左、右**分别独立**运行生产 `ec324_dual_channel_receipt.receipt.verify`，每次又重新运行真实 EC323→EC322→EC321→EC320→EC319→EC318→EC317→EC294 **既有原签章重演**。两个结果都必须为真正未解决签章分叉 `exit=2`，所有正/负信任标记必须吻合；不能用纯 unsigned SHA 一致或缓存 PASS 代替。
4. 两次昂贵验签后，再重新读取两个快照、四个 pin 文件、两份外 ZIP 和父文件并严格复比 SHA，防止把过期的第一次核验结论写进新案卷。仍存在非原子多文件读取窗口：本地不能替代可信远端事务。
5. `create-case` 生成恰好 1 份**规范 UTF-8 LF JSON**，最大 **12 KB**；包含包外父头、精确子头原 SHA、两边原 capsule/case/ACK SHA、四个原渠道 SHA、handoff/operator、签名 fork 序号和两个末行规范 SHA。两子头按**自身原 SHA 字典序**排序，所以调用者交换 left/right 也会得到完全相同的案卷字节。输出 owner-private `0600`、`O_EXCL`、文件与目录 `fsync`，绝不覆盖旧案卷、密钥或源文件。
6. `verify-case` 不是查看案卷并相信声明：先要求对**案卷整份 raw SHA**另行包外钉住，再取齐**两边所有真实原件**及父原件，执行上述完整双链复验，重造规范案卷并精确比对全原字节。案卷对外的 SHA 仅作身份绑定，不构成新 Ed25519 签名或机构裁决。

## CLI

独立命令：

- `python3 scripts/ces_cas_receipt_siblings.py create-case ... --out /private/dispute.json`：仅创建新的 unsigned 本地案卷；
- `python3 scripts/ces_cas_receipt_siblings.py verify-case ... --case-file /private/dispute.json --expected-case-sha256 <EXTERNALLY_PINNED_RAW_SHA>`：无写入、强制重演两边；
- `python3 scripts/ces_next.py audit-receipt-siblings DeliveryAudit VerifyOfflineReceiptSiblingDispute ...`：统一控制台**只允许**隔离 `-I -B verify-case`，不暴露 `create-case`、`--out`、私钥或任何 Host/Provider/CAS 写能力。

两条独立命令共有以下参数（每侧的 7 个字段都必填）：

```text
--registry-id <same_registry_id>
--expected-sequence <1..16>
--expected-prior-registry-sha256 <independent_parent_raw_SHA_or_64_zeroes>
[--prior-registry-file /private/parent.json]   # 仅序号 >=2 时必填
--left-registry-file /private/left-head.json
--left-expected-registry-sha256 <independent_left_head_raw_SHA>
--left-capsule-file /private/left-capsule.zip
--left-origin-file /private/left-origin-pin.json
--left-expected-origin-sha256 <independent_left_origin_raw_SHA>
--left-recipient-file /private/left-recipient-pin.json
--left-expected-recipient-sha256 <independent_left_recipient_raw_SHA>
--right-registry-file /private/right-head.json
--right-expected-registry-sha256 <independent_right_head_raw_SHA>
--right-capsule-file /private/right-capsule.zip
--right-origin-file /private/right-origin-pin.json
--right-expected-origin-sha256 <independent_right_origin_raw_SHA>
--right-recipient-file /private/right-recipient-pin.json
--right-expected-recipient-sha256 <independent_right_recipient_raw_SHA>
```

**返回语义：** `exit=2` + `status=offline_sibling_local_receipt_dispute_case_created_no_cas` 或 `offline_sibling_local_receipt_case_independently_reverified`，表示**两个不同的本地接收子头确实共用一个包外 SHA 钉住的父头，且当前两边既有签章历史均已重验，但没有赢家**。拒绝为 `exit=3` 权限/外部信任或历史不符、`4` 输入不合法、`5` 无法运行/环境故障，始终不输出肯定的结果。不存在成功选择赢家的 `exit=0`。两个子头相同、祖先不同、子头伪签、父头错误、内容/路径篡改以及案卷虽被重新计算 SHA 但语义篡改时，全部拒绝。

## 完全不能从这里推出的事实

- 局部**同父接收快照**分叉不等于旧 **registrar 的两条签名分叉**是不同原始争议；两件本地子快照完全可能复用**同一份已签 capsule**，仍是真实的本地并发子提交争议。输出不把两者混淆。
- `origin` / `recipient` 人员 ID 是未签声明；即使 SHA 固定，不能证明不同真人、授权机构、独立网络传输或组织共识。
- 本案卷**未签名**，不能证明外部 WORM 持久化、远端全局可见、线性化 CAS、不可回滚最新版本、时间/挑战单调或分叉赢家；要实现真正原子赢家选择，需要真实外部受信系统/组织授权，绝不可由本地代码自造成功回执。
- `receipt.verify` 重新验真的是**最新一行** EC323→EC294 原签；前面累积行在没有其逐条旧原件时只验证规范结构 SHA，不宣称逐条旧原签再执行。
- 聚焦套件使用 inherited EC321/323 轻量 fixture：第五、第六、第七 Ed25519 **真实执行**，但原 EC317/318 更深的签章链为 mock；本套件没有真正运行**完整生产原始材料** EC294→EC325、双设备包外可信渠道、PS7 原 Smoke15、Windows/macOS、真实 WORM/CAS、Git/Provider/CI/E63–E66 和最终联合验收。

功能代码：`construction/ec325_offline_receipt_siblings/proof.py` / `operator.py`；功能测试：`test_siblings.py`；独立入口：`scripts/ces_cas_receipt_siblings.py`。历史 EC324、EC323 等原签源码及原有独立 CLI 均未改动。
