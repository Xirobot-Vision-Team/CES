# EC298 — 两份独立钉住的完整签名历史：离线竞争分支取证

**施工版本 V6.08 / R298 / EC298。** 本轮只增加一次**离线比对**；不增加任何原签署、密钥托管、自动分叉裁决、Provider/Inbox 请求或原 Router 权限。

## 精确输入和真实信任前提

操作员准备**两套分别完成的 EC297 完整证据**，每套包含：

- `inputs_file`：原 EC297 `ces.ec297.offline_rotation_lineage_inputs.v1`，3～16 代签名检查点全链，逐次完整原 EC296 bridge。
- `commitment_file`：其离线生成的路径无关承诺 JSON。
- 必须从各自**独立可信、远离候选本地文件的渠道**取得四个完整小写 SHA256：`expected_commitment_sha256`、`expected_root_tip`、`expected_latest_tip`、`expected_latest_bridge_sha256`。

八个 SHA 均需外部显式输入；CLI 不从上传的本地文件中猜“正确 SHA”，不会自动挑选最新 fork。程序检查完整 SHA 格式和两套证据的一致性，但**程序自身无法证明八个值真的已安全存入两个独立不可回滚库**。两套候选不同并不自动说明哪套更可信。

## 运行：比较而不写业务

`a` 和 `b` 是两份独立的历史，而不是旧/新轮换钥。以下 12 个参数都必填，完整的绝对路径不能省略：

```bash
python3 -I -B scripts/ces_anchor_conflicts.py compare-lineages \
  --a-inputs-file /private/A-inputs.json \
  --a-commitment-file /private/A-commitment.json \
  --a-expected-commitment-sha256 A_64_LOWERCASE_HEX \
  --a-expected-root-tip A_64_LOWERCASE_HEX \
  --a-expected-latest-tip A_64_LOWERCASE_HEX \
  --a-expected-latest-bridge-sha256 A_64_LOWERCASE_HEX \
  --b-inputs-file /private/B-inputs.json \
  --b-commitment-file /private/B-commitment.json \
  --b-expected-commitment-sha256 B_64_LOWERCASE_HEX \
  --b-expected-root-tip B_64_LOWERCASE_HEX \
  --b-expected-latest-tip B_64_LOWERCASE_HEX \
  --b-expected-latest-bridge-sha256 B_64_LOWERCASE_HEX \
  --out /private/forensics/EC298-report.json
```

**上方 `A_64_LOWERCASE_HEX/B_64_LOWERCASE_HEX` 是占位文字，必须使用真实值。** `--out` 可以省略；给出时只在已验证成功后，以原 EC295 owner-only 私有父目录规则**独占新建 0600 并 fsync**，绝不覆盖旧报告。输出的报告 JSON 不带本地绝对路径，仅携带散列、签名公钥、观察到的同父分支指纹和明确的免责声明。没有重新持有完整原 signed checkpoint / bridge 文件就不能仅凭摘要独立复验它。

统一控制台只允许精确命令：

```bash
python3 -I -B scripts/ces_next.py audit-conflicts DeliveryAudit CompareLineages \
  <与上述相同的十二个 --a-* / --b-* 参数>
```

它只比较/打印，不写报告或持久化任何业务数据。原 Router 74 条和其中 11 个 `HOST_REQUIRED run` 仍保持默认拒绝；`audit-conflicts` 不在原 Router 中新增授权，也不是 `DeliveryAudit.Run`。

## 哪些事实会生成分叉证据

**(1) 同一 EC296 旧签名检查点末端出现两个不同的签署后继。** 两条完整历史必须先各自通过原 EC297 的 `build_commitment` 和四个外部 SHA 核验；再匹配完全相同的 `(old_policy_sha256, old_checkpoint_tip_sha256)`。若两张原 EC296 完整验证过**四方**签名的 bridge 指向不同的 `(new_policy_sha256, new_checkpoint_tip_sha256)`，生成 `two_ec296_four_vote_rotation_bridges_from_same_old_tip`。包含两张 bridge SHA、各自签名 claim SHA、旧/新角色公钥和目标 pin；证据说明真实签名密钥对相同旧锚点签过竞争的转换，不判定哪个转换最终合法/最新。

**(2) 同一 EC295 策略和同一直接父检查点有两个不同的双签子节点。** 除 EC297 完整检验外，对实际用于比对的所有 checkpoint 再次做原 EC295 **完整链与原 EC294 Host 签回验证**（包括签名和输入 pinned tip），并在同一个 `(policy_sha256, sequence, previous_checkpoint_sha256)` 下比较完整 checkpoint SHA。不同 SHA 生成 `two_ec295_signed_checkpoint_children_of_same_parent`，记录两边完整 checkpoint SHA / 声明 SHA / keeper+witness 公钥。不比较单纯同名文件、路径、未签 payload 或签名者姓名。

**(3) 同证据 / 单纯延伸。** 两边整个 `epochs/bridges` 完全相同，返回 `identical_lineage_evidence`；一方为另一方**逐张完全相同**的已验证 epoch 和 bridge 前缀时，返回 `a_is_verified_prefix_of_b` / `b_is_verified_prefix_of_a`。新增第四代并不是与第三代竞争。

**(4) 仅哈希不同但没有同一签名父节点。** 返回 `distinct_histories_without_proven_shared_parent_fork` / `inconclusive`，不能做“发现作弊”结论。两方原 EC294 operation/job/policy/Host/EC227 身份不同则拒绝比较，而不是把不同业务误报成分叉。

## 退出码和承诺

| 退出码 | 状态 | 含义 |
|---|---|---|
| `0` | `verified_no_conflict_observed_between_supplied_histories` | 仅在所提供的两份历史之间找到相同或严格已验证前缀；不证明没有第三条分支，也不能断言谁是全球最新 |
| `2` | `signed_competing_evidence` | 两份都已通过完整验签，观察到共享的**精确签名父节点**和两份竞争的已签后继；需人工治理和单独外部保全 |
| `2` | `inconclusive` | 两份均已验证但证据不足，不能据 SHA 不等猜测签名冲突 |
| `3` | `permission_denied` | 缺少可信 SHA 输入、外部 pin 不匹配、签名、身份或者语义断言失败 |
| `4` | `invalid_input` | JSON/参数/路径/格式不满足明确输入契约 |
| `5` | `unavailable` | 输入读取/运行环境等未满足，永远不冒充成功 |

独立保存报告后，第三方可以带**外部独立保留**的完整 report SHA 再验证：

```bash
python3 -I -B scripts/ces_anchor_conflicts.py verify-report \
  --report-file /private/forensics/EC298-report.json \
  --expected-report-sha256 REPORT_64_LOWERCASE_HEX \
  <与上面相同的十二个 --a-* / --b-* 参数>
```

`verify-report` 重新验两条原始历史并重新计算确切报告，要求重新计算的报告**完全等于**已带摘要的原报告。外部 SHA 保管是否可靠由外部人员负责；本地验算不能认证“报告外部归档”已经真实发生。

## 不作出的保证及最终集中验收

EC298 不读取原 EC227 当下磁盘 HMAC 账，不请求网络，不运行原 EC294/EC293/EC225 Host，不生成私钥，不解释真实人员身份/串谋意图，也不证明可信 UTC、监管上的双重签字或外部不可变存证。**两条都有效可以是正常重签/重部署，也可是真实治理冲突；程序只能提供签名冲突的密码学候选证据，不提供惩罚性/合规性判断。** 如果原钥泄露，程序也无法裁定谁是真签署人；第三个未展示的历史分叉不会被搜索到。报告并不包含完整敏感证据原文，移机核验需要完整原始输入随行。

本轮单机集成 fixture 使用实际原 EC294 Unix 签名 Host、原 EC227 HMAC/fsync、原 EC295/296 Ed25519 签章，但远端 Provider/Inbox 为原测试模拟，多个“角色”是本机独立密钥，并非组织独立真人。原 PowerShell7 15 Smoke、Windows/macOS、Git/CI、E63–E66、生产 Provider/Inbox、独立多方可信保管、实际分叉治理及最终联合验收继续**待用户集中验证**。EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、Quality PASS=false 与最终验收 `NOT_STARTED` 全部保留。
