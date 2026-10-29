# EC319 — 原字节签收的第五独立保管角色离线登记簿

**版本 V6.29/R319/EC319，严格离线，有限 0–4 个登记。** 本 EC 在 EC318 三签字节不变的基础上增加一份**第五密钥的独立签名历史**。`bootstrap`、`append` 和 `compare` 只在单独的 `scripts/ces_cas_registrar.py`；统一 `ces_next.py` 只能调用 `verify`。没有 Host/CAS/Provider 写权限。

## 明确的信任边界

- 登记者必须得到**包外独立固定**的登记者 ID、公钥、首次 genesis signed-record SHA、当前 signed-record SHA 和 snapshot **整文件原字节 SHA**；历史 EC316 trust/chain/ledger/latest cert/challenge 原件根与 ZIP 原字节 SHA 被第五方真签钉住。登记者公钥不能仅从登记簿内自述认定为组织已授权。
- bootstrap 真正重放 EC317 ZIP 内旧 EC316→EC294 全签名后才打开第五把私钥；每次 `append` 先重新重验**每个旧事件**和新 EC318 offer→ACK→closure 三真签及全部历史签名，再以单独 `CES/EC319/...` Ed25519 域签名。`verify` 无任何私钥读取。
- 一个**注册周期**内拒绝重复 offer/ACK/closure 整原 SHA；拒绝复用本周期旧登记 challenge、之前所有所见 EC318 发送/接收/最终确认 challenge、创世 registrar challenge 与被钉住的**旧 EC316 最新 challenge**。旧 EC316 自身已严格检查其历史证书挑战不同，但本轮不声称枚举了所有旧 EC316 证书挑战与新周期交叉去重。
- 每份 `append` 创建**全新** 0600 O_EXCL/fsync 快照文件，前缀 signed records 原字节不重写。每个新签名条目含确切上一个已签记录的完整 raw SHA、严格顺序号、genesis raw SHA、原 ZIP SHA、三旧签收文件 raw SHA、两传输身份与挑战、登记挑战，以及全部真签重放结果。所有磁盘输入为 owner-private 单硬链接 0600 常规文件与规范 JSON；材料 map 只负责定位文件，不能为签名增权。
- `compare` 同时独立重验两个由包外 SHA 固定的快照及**两边全部原件**。若共享前驱上同一序号出现两份不同、均有效的第五方签名，返回 `exit_code=2` 和双分支 raw SHA 冲突证据；一致或真签前缀关系返回 `exit_code=0`。`exit=2` 表示**可核实的离线签名分叉**，不是文件损坏的普通拒绝。
- **不具备**外部持久不可回退 WORM、单一 head 线性化 CAS、全球最近/唯一、真实组织授权或撤销、真实两机器、人事独立、时间可信度、物理交付或生产业务完成证明。用旧 snapshot + 旧有效独立 pin 可以在不同机器签出合法兄弟分支；这正是 `compare` 能检测而单独 `verify` **无法防止**的风险。必须把 head pin 真正交给外部可信登记服务才能升级此边界。

## 命令与输入

所有路径都应为**规范 POSIX 绝对路径**，输入私有父目录 0700、原件 0600；bundle 与完整历史源原 SHA 保持不变。新快照 `--out` 必须尚不存在，不能用旧快照文件路径。生成原 registrar 私钥时使用独立的 Ed25519 32 字节种子文件，权限 0600；不要共享 EC316 两把或 EC318 两把签字私钥，别把密钥上传到项目归档。

**1. 建立一个已经真正重验原始 EC317 ZIP 的 genesis（不登记任何签收）**：

```sh
python3 scripts/ces_cas_registrar.py bootstrap \
  --registry-id my_offline_registry --registrar-id my_registrar \
  --registrar-public-hex REGISTRAR_PUBLIC_HEX \
  --registrar-epoch-challenge-sha256 INDEPENDENT_EPOCH_CHALLENGE_SHA \
  --bundle-file /private/site/evidence.zip --expected-bundle-sha256 ZIP_RAW_SHA \
  --chain-file /original/site/chain.json --expected-chain-sha256 CHAIN_RAW_SHA \
  --ledger-manifest-file /original/site/ledger.json \
  --expected-ledger-manifest-sha256 LEDGER_RAW_SHA \
  --expected-latest-certificate-sha256 CERT_RAW_SHA \
  --expected-latest-challenge-sha256 OLD_LATEST_CHALLENGE_SHA \
  --custodian-a-id keeper_a --custodian-a-public-hex KEEPER_A_PUBLIC_HEX \
  --custodian-b-id keeper_b --custodian-b-public-hex KEEPER_B_PUBLIC_HEX \
  --private-key-file /private/registrar/key32.bin \
  --out /private/registrar/registry-0.json
```

`--chain-file` 与 `--ledger-manifest-file` 是**源机器原绝对路径文字**，即使本机已移机也不能重新命名；签名原件读取只能通过 EC317 验证过的 ZIP 路径映射。

**2. 写一个 unsigned 的本机路径索引 `materials.json`。** 它不进入第五方签名；变更时需要依照相同 raw SHA 重新验所有真签。首先有一份独立 `genesis_bundle_file`，然后按 sequence 从 1 开始排列**当前所有**签收材料：

```json
{
  "schema": "ces.ec319.local_unsigned_material_path_map.v1",
  "genesis_bundle_file": "/private/site/evidence.zip",
  "receipts": [
    {"sequence": 1, "bundle_file": "/private/site/evidence.zip",
     "offer_file": "/private/site/offer-1.json", "ack_file": "/private/site/ack-1.json",
     "closure_file": "/private/site/closure-1.json"}
  ]
}
```

写入文件的 JSON 必须是**ASCII sorted-key compact canonical JSON，末尾恰好 LF**，`0600`/单硬链接/受限绝对父路径，不是上面展示用的缩进文本。可以在 Python 中使用 `json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'` 生成。

**3. 向旧 snapshot 追加一份已完整签署的 EC318 签收**。所有 `expected-*` SHA 都指**文件整原字节**（非内部 canonical binding digest），`--materials-file` 含旧 N 份 + 新 1 份。必须包外冻结旧 snapshot/genesis/head 三份 SHA。除已列的参数外没有其它信任输入：

```sh
python3 scripts/ces_cas_registrar.py append \
  --registry-file /private/registrar/registry-0.json \
  --expected-registry-sha256 PRIOR_SNAPSHOT_RAW_SHA \
  --materials-file /private/site/materials.json \
  --expected-genesis-raw-sha256 GENESIS_SIGNED_RECORD_RAW_SHA \
  --expected-head-raw-sha256 PRIOR_HEAD_SIGNED_RECORD_RAW_SHA \
  --registrar-id my_registrar --registrar-public-hex REGISTRAR_PUBLIC_HEX \
  --sender-id sender_id --sender-public-hex SENDER_PUBLIC_HEX \
  --receiver-id receiver_id --receiver-public-hex RECEIVER_PUBLIC_HEX \
  --sender-exchange-challenge-sha256 SENDER_CHALLENGE_SHA \
  --receiver-exchange-challenge-sha256 RECEIVER_CHALLENGE_SHA \
  --sender-confirmation-challenge-sha256 CLOSE_CHALLENGE_SHA \
  --registrar-entry-challenge-sha256 FRESH_REGISTRAR_CHALLENGE_SHA \
  --offer-original-raw-sha256 OFFER_RAW_SHA \
  --ack-original-raw-sha256 ACK_RAW_SHA \
  --closure-original-raw-sha256 CLOSURE_RAW_SHA \
  --private-key-file /private/registrar/key32.bin \
  --out /private/registrar/registry-1.json
```

`append` 回传**新快照 SHA、新头 signed-record SHA、同一 genesis signed-record SHA**。把三件输出值在包外独立留存，而不是把它们写回旧快照。

**4. 独立收件审计全历史（可从不同物理路径读取相同字节的 ZIP/收据）**：

```sh
python3 scripts/ces_cas_registrar.py verify \
  --registry-file /private/registrar/registry-1.json \
  --expected-registry-sha256 CURRENT_SNAPSHOT_RAW_SHA \
  --materials-file /private/site/materials.json \
  --expected-genesis-raw-sha256 GENESIS_SIGNED_RECORD_RAW_SHA \
  --expected-head-raw-sha256 CURRENT_HEAD_SIGNED_RECORD_RAW_SHA \
  --registrar-id my_registrar --registrar-public-hex REGISTRAR_PUBLIC_HEX
```

只读统一控制台使用**新名字**，不能覆盖先前 EC304 的 `audit-registry`：

```sh
python3 scripts/ces_next.py audit-transfer-registry \
  DeliveryAudit VerifyOfflineTransferRegistry \
  --registry-file /private/registrar/registry-1.json \
  --expected-registry-sha256 CURRENT_SNAPSHOT_RAW_SHA \
  --materials-file /private/site/materials.json \
  --expected-genesis-raw-sha256 GENESIS_SIGNED_RECORD_RAW_SHA \
  --expected-head-raw-sha256 CURRENT_HEAD_SIGNED_RECORD_RAW_SHA \
  --registrar-id my_registrar --registrar-public-hex REGISTRAR_PUBLIC_HEX
```

**5. 双视图同根冲突检查**：

```sh
python3 scripts/ces_cas_registrar.py compare \
  --left-file /private/site/registry-left.json \
  --expected-left-sha256 LEFT_SNAPSHOT_RAW_SHA \
  --left-materials-file /private/site/materials-left.json \
  --expected-left-head-raw-sha256 LEFT_HEAD_SIGNED_RECORD_RAW_SHA \
  --right-file /private/site/registry-right.json \
  --expected-right-sha256 RIGHT_SNAPSHOT_RAW_SHA \
  --right-materials-file /private/site/materials-right.json \
  --expected-right-head-raw-sha256 RIGHT_HEAD_SIGNED_RECORD_RAW_SHA \
  --expected-genesis-raw-sha256 ONE_COMMON_GENESIS_SIGNED_RECORD_RAW_SHA \
  --registrar-id my_registrar --registrar-public-hex REGISTRAR_PUBLIC_HEX
```

`compare` 从两侧完整重验出确实在同一个已签父节点出现两个不同已签子条目后报告**精确哪一序号**和两个互斥条目整原 SHA，输出没有写操作。`max=4` 是按单个 genesis 注册周期，不能由重复启用旧 genesis 无端宣称突破全局唯一限制。

## 测试与后续验收

- `PYTHONPATH=construction PYTHONDONTWRITEBYTECODE=1 python -B -m unittest construction.ec319_offline_transfer_registry.test_registry_structure -v`：这是**只检测登记逻辑 + 真实第五把 Ed25519**的轻量结构测试，EC317/EC318 内部重放在此套件中用测试替身隔离，不能冒充完整旧全链验真。
- `PYTHONPATH=construction PYTHONDONTWRITEBYTECODE=1 python -B -m unittest construction.ec319_offline_transfer_registry.test_registry -v`：拟运行**所有真实上游 Ed25519 固定全链证据**的较重套件，工程代码已包含，当前受原 EC311→EC318 历史 fixture 长时间初始化限制，未作为本轮完整 PASS 交付。需统一协同重测。
- 用户仍需确认实际组织 registrar 公钥授权与撤销、双机离线交接、head 不可回滚独立保存、跨历史所有 nonce、可信时间及外部 WORM/CAS，以及原 15 项 PowerShell7/native、Windows/macOS/Provider/Inbox/Git/CI/E63–E66 和最终全业务验收。旧 EC249、EC250、B001 与全局 Quality 状态不改。
