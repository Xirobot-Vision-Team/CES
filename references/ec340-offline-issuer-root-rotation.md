# EC340 — 离线发行者信任根双代轮换（单跳）与独立见证快照协议

> **施工包 V6.50 / R340 / EC-340；不是法定机构证书，也不是历史 EC339 授权的续期。** 本轮仅实现 EC339 的 *epoch 1 → epoch 2* 一个有界交接；不声称支持第三代及任意多跳世界状态。**全程不触发远端 CAS/WORM 或 business 持久化。**

## 一、真实问题与安全边界

EC339 的四发行者 roster SHA 是单版本的外部信任根；四把发行者私钥分别真签授权 grant、针对外部 challenge 的 24h 状态。在轮换之后，**即便原旧签名仍为真**，也不能凭这些原签判断旧根在新的评估时刻是否继续有效。错误做法包括用新 issuer 公钥复验旧 grant、修改旧 roster/政策重签、或仅凭 `--evaluation-utc`/本机时间证明根未退役。

EC340 增加独立的、严格格式的 *successor roster*，其 **整份 raw SHA-256** 引用当前 EC339 **predecessor** roster 及 EC338 policy、transfer，并只准 `epoch:2`，包含新四发行者 ID/public keys、轮换 ID/nonce、旧根退役生效 UTC。四角色各需要 **旧 issuer 和新 issuer 各一把不同 Ed25519 私钥**签署一个完全相同的新根原件 SHA，签名领域包括 `old|new` 与 `sender|carrier|receiver|witness`，总共八份互不复用的角色签名原件。旧/新 issuer ID、公钥需全部不同；新发行者不得复用 EC338 操作人公钥。

额外 **独立 observer（监督见证方）** 从用户真正独立受信渠道固定其 roster SHA；观察方的独立 ID/公钥/声明组织不得重用任何旧新 issuer ID、公钥、四操作人的公钥或操作人的组织 ID。观察方对旧根 `retired`、新根 `active`、八份角色签名**分别整原 SHA**、旋转原件、接收方外部挑战、`observed_utc`→`expires_utc` **不超过24小时**的声明再次独立 Ed25519 真签；这证明“该公钥声称此状态”，**不证明观察方已真实查询完全部机构撤销登记，也不证明其时钟可信**。

## 二、写入与签署步骤（仅独立工具，不经统一只读入口）

**0.** 保留 EC339 原 policy、issuer roster、四原 grant、四原 status、四 EC338 角色回执与 EC337 archive 的原始字节和原包外 SHA；不要改旧的签名或授权原件。先由真实组织决策链在本程序之外批准新 root，离线产生 **四把新发行者私钥**（各自 owner-private 0600）、**一把见证私钥**，并独立保管新 root SHA/公钥。绝对不要把这九把密钥搬到统一只读入口上。

**1.** 私有规范原件 `issuer-config.json` 的字段仅有 `issuers`，按 `sender,carrier,receiver,witness` 排序，每项仅 `role,issuer_id,issuer_public_hex,subject_organization_id`；与 EC339 中的四个 `actors[].organization_id` 一一对应。JSON 必须 `sort_keys=True`, `separators=(',',':')`, `ensure_ascii=True`, UTF-8 加 LF，owner-private 0600，不含额外字段。

```text
python -I -B scripts/ces_cas_issuer_rotation.py create-roster \
  --out /private/ec340/successor-roster.json \
  --policy-file /private/ec338/policy.json --expected-policy-sha256 <21项旧包外SHA之一> \
  --authority-roster-file /private/ec339/roster.json --expected-authority-roster-sha256 <旧roster外部SHA> \
  --issuer-config-file /private/ec340/issuer-config.json --expected-issuer-config-sha256 <配置原SHA> \
  --rotation-id rotation_340_example --rotation-nonce-sha256 <新独立64位小写hex> \
  --effective-utc 2026-10-25T11:00:00Z
```

此时输出的是**本地候选原件 SHA**，还不是经过外部审查的当前 root pin。必须经独立渠道确认 successor roster 的 whole SHA，并另由**接收方受信根状态渠道**提供 `--expected-current-root-sha256` 和 `--expected-current-root-epoch 2`，防止攻击者把已过期的 1 代称作最新版。root 自身和这两项外部输入不应相互自动复制、互相视作证明。

**2.** 八位实际密钥保管人（旧 `old` / 新 `new` × 4 角色）分别运行 `sign-edge`，输入**同一份原 successor-roster SHA**及旧 policy/roster SHA。示例仅为新 sender，其他七份必须分别完成：

```text
python -I -B scripts/ces_cas_issuer_rotation.py sign-edge \
  --out /private/ec340/new-sender-edge.json \
  --private-key-file /private/keys/new-sender-ed25519.raw \
  --side new --role sender \
  --policy-file /private/ec338/policy.json --expected-policy-sha256 <可信policy SHA> \
  --authority-roster-file /private/ec339/roster.json --expected-authority-roster-sha256 <可信旧root SHA> \
  --successor-roster-file /private/ec340/successor-roster.json \
  --expected-successor-roster-sha256 <可信新root SHA>
```

每个 Ed25519 签名**按角色+侧绑定独立领域**，原文精确绑定 `predecessor_roster_original_raw_sha256`, `successor_roster_original_raw_sha256`, 两个 issuer ID、公钥中被该侧选择的一个、轮换 ID/nonce、epoch、effective UTC、role 和 side。接收者必须分别从真实独立保管方取得每份签名文件的 whole SHA。`sign-edge` 每次最多使用**一把**私钥，不支持聚合私钥快捷通道。

**3.** 建立独立 canonical 见证信任 roster（必须另由外部真实信任渠道固定其 raw SHA）：

```json
{"schema":"ces.ec340.independent_root_observer_trust.v1","transfer_id":"ec339_transfer_001","policy_original_raw_sha256":"<受信旧policy SHA>","observer_id":"root_observer_340","observer_organization_id":"org_independent_observer","observer_public_hex":"<见证 Ed25519 raw 公钥 hex>","independent_out_of_band_approval_required":true}
```

见证方实际查询自己的组织登记（这一步**不由程序自动完成**）后用 `issue-observation` 真签一份候选原件。此命令需要全部 8 个 `--old-sender-edge-file` / `--expected-old-sender-edge-sha256` 等对应参数，以及旧 policy/旧 root/新 root/observer root 文件及对应 SHA，另带 `--out`, `--private-key-file`, `--verifier-challenge-sha256`, `--observed-utc`, `--expires-utc`。私钥与所有签名原件必须各自不同路径。此命令**先实际验完八个角色签名与见证信任公钥，再使用见证私钥**；签名时刻只是见证方声称的观察时刻。见证原件还需接收方独立 whole SHA pin。

写入行为只发生在**独立** `create-roster|sign-edge|issue-observation`，都使用 owner-private `0600`、规范 LF JSON、`O_EXCL` 不覆盖、文件/目录 fsync 并在写后复读；不发送、安装或写远端。只读 `verify-rotation` 无私钥参数。

## 三、接收方真正只读全链验证

**输入合计 32 项分别受信文件原 raw SHA：** 已有 EC339 的 21 项（EC337 7 + EC338 5 + EC339 9），新增新 root 1 + 八份 issuer 侧真签 8 + observer roster 1 + observer signed status 1 = **11 项**。另外接收方必须有独立确定的 `expected_current_root_sha256`（与新 root 原 SHA **值应相等但信任来源不同**）、`expected_current_root_epoch=2`、challenge SHA 和两个不同用途 UTC：

- **`evaluation_utc`：** 原 EC339 旧签和 status 所属的**历史评估时刻**，必须严格早于 successor `effective_utc`；四份 EC338 旧角色回执中的签署人**自报时刻**也必须在旧根退役前，且仍符合旧 EC339 grant 有效窗口。不能让已退役 issuer grants 被当成新根下的新签授权。
- **`root_evaluation_utc`：** 新 root 状态的**操作员评估时刻**，必须晚于或等于 successor `effective_utc`，处于独立见证签名声明的 `[observed_utc,expires_utc)` 内，且不得早于历史评估时刻。**仅是操作员输入，不自动成为受信时钟。**
- **`verifier_challenge_sha256`：** 与原 EC339 四份挑战 status 和新 root status 都必须严格匹配同一独立包外 nonce SHA。软件不能凭 SHA 证明 nonce 随机、独立保管、只用一次或在线 freshness。

接受时验证顺序：先严格校验外部 epoch/pins/格式与旧新根结构、八份**真签**及独立见证身份/状态/挑战/时窗；随后**真实调用 EC339** 重验旧四授权/四挑战状态、EC338 四角色真签前序 raw SHA 链及 EC337 运输 ZIP 和其内嵌原件；最后复读新旧原件 SHA、旧 grant/status/receipt 和完整 ZIP SHA。任一失败 `permission_denied/3`、`invalid_input/4` 或 `unavailable/5`；全部验证可接受仍只输出 `exit_code:2`、`...unresolved`。

独立只读命令：

```text
python -I -B scripts/ces_cas_issuer_rotation.py verify-rotation \
  <原EC339 verify-authority所需全部21项原件路径和 SHA 参数> \
  --successor-roster-file /private/ec340/successor-roster.json \
  --expected-successor-roster-sha256 <可信 successor whole SHA> \
  --expected-current-root-sha256 <另一个真正外部渠道受信的当前根SHA> \
  --expected-current-root-epoch 2 \
  --observer-roster-file /private/ec340/observer-root.json \
  --expected-observer-roster-sha256 <可信observer root原SHA> \
  --root-observation-file /private/ec340/root-observation.json \
  --expected-root-observation-sha256 <可信observer签名原SHA> \
  --old-sender-edge-file /private/ec340/old-sender-edge.json \
  --expected-old-sender-edge-sha256 <可信edge SHA> \
  <其他七份old/new x roles同名edge参数> \
  --root-evaluation-utc 2026-10-25T11:40:00Z
```

上述 `<...>` 只是格式说明，不可直接照录成实际 SHA。具体完整参数名见：`python -I -B scripts/ces_cas_issuer_rotation.py verify-rotation --help`。

**统一入口仅提供固定只读验签：**

```text
python -I -B scripts/ces_next.py audit-issuer-root-rotation \
  DeliveryAudit VerifyCrossSignedIssuerRootRotation <全部上述参数>
```

统一路由对子进程调用 `python -I -B ... verify-rotation`，核对**确切输入、34个成功响应字段/严格拒绝响应结构、exit2 与全部非证明标记**，无 `create-roster|sign-edge|issue-observation` 的变体入口，拒绝私钥与写入参数。即使证明了签署者手中确有八把可验的不同 Ed25519 私钥，也**不能**推断九位物理真人、法律身份、机构合规授权或可信证书链。

## 四、威胁边界及需人工协助事项

- **单跳**：旧 root 固定 EC339 epoch1，成功 root 固定 EC340 epoch2；不支持 2→3、完整多年代 root lineage、同时分叉裁决。未来轮次要单独施工。攻击者若取得外部受信渠道，仍可谎报 `current_root_epoch=2` / SHA；本地不提供全球最新根证明。拒绝 old/new 同 key/ID/actor key，只防此一跳本地 key ABA，不保证全球跨年代没有回归。
- **时间与撤销**：见证真签的 retired/active 是见证方**签署的声明**；并非实际完整登记册、独立 UTC 校时、在线 OCSP/CRL 或全球一致性。`root_evaluation_utc` 和旧 `evaluation_utc` 是外部给定的字面时间；受信时间需要**额外真实独立渠道**和用户人工验收，不能由模拟自证。
- **历史事实**：旧 EC339 授权在退役后的新 epoch 中**绝不升级为有效的新授权**；新的真实交接需 EC338/339 新 policy、真正的新 grant、收据和完整实际独立受信证据。本轮只追溯旧授权在历史时刻的真实性。EC317/318 深层旧 fixture 仍 MOCK，不可据此宣称无 mock 的全生产历史真实通过。
- **最终统一验收**：真实发行机构及独立见证方资格、受信根保管/轮换/撤销登记、独立新根 SHA 和 epoch 经谁授予、真实性能/可信 UTC、两台以上设备/多方独立密钥保管、32 项外部 SHA 保管、无 MOCK 的 EC294→340 全历史原签、PS7/15 原 Smoke/Windows/macOS/Git/CI/Provider/远端 CAS/WORM/E63–E66 与真实外部 nonexecution/latest/winner 均待统一协助。

本轮参考实现：`construction/ec340_issuer_root_rotation/{rotation,operator,test_rotation}.py`；独立 `scripts/ces_cas_issuer_rotation.py`，统一只读 `scripts/ces_next.py audit-issuer-root-rotation`；本轮记录 `EC-340.md`。
