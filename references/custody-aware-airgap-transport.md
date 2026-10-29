# EC337 — 原始旧签材料 Airgap 离线运输及独立信任交接

## 0. 先决条件

- **源端**已经用 **真实非 MOCK 的生产旧签**完成 EC334 `create-plan`、EC335 `create-closure`、`prepare-map`，且旧 EC335 closure 只含真正观察到的受保护 ORIGINAL 读取，旧 ZIP 的原 bytes 尚在。准备目标机确定的 **绝对** `destination-root` 生成 map；不得在搬运途中改 map 内旧签路径或目标绝对路径来适配新机。
- **六项独立 whole raw SHA 输入**：`PLAN_SHA` = EC334 plan；`CLOSURE_SHA` = EC335 closure；`MAP_SHA` = EC335 map；`HANDOFF_SHA` = EC333 handoff；`LEFT_SHA`、`RIGHT_SHA` = 左右 EC331 original manifests。六项须另由受信包外来源固定。**不能让任何一个 JSON 自带的哈希决定它自己的可信值**。
- 接收端还需另取得 `BUNDLE_SHA`（完整运输 ZIP 原字节 SHA），共七项；同一来源直接将 manifest 和七项数字一起发来，未经独立外部确认**不符合独立 custody**，虽然工具仍能做有限数学相等检查。

## 1. 源端生成（写入仅本地一个私有包，不覆盖）

```bash
python3 -I -B scripts/ces_cas_airgap_transport.py create-bundle \
  --out /source/private/ec337-whole-original-transport.zip \
  --first-hop-plan-file /source/private/ec334-plan.json \
  --expected-first-hop-plan-sha256 "$PLAN_SHA" \
  --closure-file /source/private/ec335-closure.json \
  --expected-closure-sha256 "$CLOSURE_SHA" \
  --map-file /source/private/ec335-map.json \
  --expected-map-sha256 "$MAP_SHA" \
  --expected-handoff-sha256 "$HANDOFF_SHA" \
  --left-expected-manifest-sha256 "$LEFT_SHA" \
  --right-expected-manifest-sha256 "$RIGHT_SHA"
```

程序生成 `manifest.json`、`custody/BLANK_EXTERNAL_TRUST_SLOTS.json`、三个**原始规范控制文件**及 `originals/0001.bin`...全体**原始持久文件**。不按内容去重而丢失不同旧原路径需要的原件；完整 ZIP 字节/每个内部文件完整 SHA 和 ZIP 内再嵌套成员均受保护。`BUNDLE_SHA` 是程序在源端**本地测量**的候选值，应交给第三方**另外固定**，它本身不是外部认证。

## 2. 人工 custody 交接记录（归档内故意全空，必须在归档外保存）

| 独立槽位 | 从谁 / 通过哪个独立可信渠道取得 | 接收端人工记录 |
|---|---|---|
| BUNDLE_SHA（整份运输 ZIP 原 SHA） | 独立见证/交接方，不从待验 ZIP 自取 | **待人工填写** |
| PLAN_SHA、CLOSURE_SHA、MAP_SHA | 各自原控制原件独立可信保管记录 | **待人工填写** |
| HANDOFF_SHA、LEFT_SHA、RIGHT_SHA | 旧历史根原件的独立可信保管记录 | **待人工填写** |
| 出具人、时间、物理介质、独立信道、身份核验 | 用户/机构独立线下审查 | **待人工填写** |
| 历史旧签、OS 权限、外部 CAS/WORM 验收人 | 最终联合验收 | **未验证** |

归档内的 `custody/BLANK_EXTERNAL_TRUST_SLOTS.json` 故意留下**七个 null 原 SHA 槽**以及空机构字段；被批准的操作者可以**在归档外复制**这个表填写，但程序从来不读取填好的工作表作为受信源。没有任何组织名称、授权、真实签名或第三方证明被自动生成。

## 3. 接收端只读检查归档（不会产生任何复制文件）

```bash
python3 -I -B scripts/ces_cas_airgap_transport.py inspect-bundle \
  --bundle-file /receiver/private/transport.zip \
  --expected-bundle-sha256 "$BUNDLE_SHA" \
  --expected-first-hop-plan-sha256 "$PLAN_SHA" \
  --expected-closure-sha256 "$CLOSURE_SHA" \
  --expected-map-sha256 "$MAP_SHA" \
  --expected-handoff-sha256 "$HANDOFF_SHA" \
  --left-expected-manifest-sha256 "$LEFT_SHA" \
  --right-expected-manifest-sha256 "$RIGHT_SHA"

# 统一控制台**只读**入口，无 create/install 权限：
python3 -I -B scripts/ces_next.py audit-airgap-transport \
  DeliveryAudit VerifyPinnedAirgapOriginalTransport \
  --bundle-file /receiver/private/transport.zip \
  --expected-bundle-sha256 "$BUNDLE_SHA" \
  --expected-first-hop-plan-sha256 "$PLAN_SHA" \
  --expected-closure-sha256 "$CLOSURE_SHA" \
  --expected-map-sha256 "$MAP_SHA" \
  --expected-handoff-sha256 "$HANDOFF_SHA" \
  --left-expected-manifest-sha256 "$LEFT_SHA" \
  --right-expected-manifest-sha256 "$RIGHT_SHA"
```

必须将接收 ZIP 放在 owner `0700` 的私有父目录中，文件 owner `0600`。纯只读 `inspect` 不要求旧签原件路径在接收端存在。

## 4. 明确授权安装并重新校验（控制文件 + 全部原始文件）

在接收机**提前创建**两个不重叠的私有根，且用 EC335 已 SHA 固定 map 指定的 **完全相同目标绝对根**：

```bash
mkdir -m 700 /receiver/private/controls /receiver/private/originals
python3 -I -B scripts/ces_cas_airgap_transport.py install-bundle \
  --bundle-file /receiver/private/transport.zip \
  --expected-bundle-sha256 "$BUNDLE_SHA" \
  --expected-first-hop-plan-sha256 "$PLAN_SHA" \
  --expected-closure-sha256 "$CLOSURE_SHA" \
  --expected-map-sha256 "$MAP_SHA" \
  --expected-handoff-sha256 "$HANDOFF_SHA" \
  --left-expected-manifest-sha256 "$LEFT_SHA" \
  --right-expected-manifest-sha256 "$RIGHT_SHA" \
  --control-root /receiver/private/controls \
  --destination-root /receiver/private/originals
```

控制文件实际位置固定为 `/receiver/private/controls/ec334-plan.json`、`ec335-closure.json`、`ec335-map.json`；源原件目的地按原受信 map **精确**安装于 `destination-root` 内。任何目标既存文件拒绝覆盖，不会无声“修补”旧原件。遇异常只尽力删除本进程创建且 inode 身份未变的文件及空目录；**不保证跨文件事务的 OS 级原子性或在掉电/kill -9 后完全自动回滚**，必要时人工检查残留。

## 5. 必须随后由 EC336 真正重放历史签名

```bash
python3 -I -B scripts/ces_cas_relocated_signed_replay.py verify-signed-replay \
  --first-hop-plan-file /receiver/private/controls/ec334-plan.json \
  --expected-first-hop-plan-sha256 "$PLAN_SHA" \
  --closure-file /receiver/private/controls/ec335-closure.json \
  --expected-closure-sha256 "$CLOSURE_SHA" \
  --map-file /receiver/private/controls/ec335-map.json \
  --expected-map-sha256 "$MAP_SHA" \
  --expected-handoff-sha256 "$HANDOFF_SHA" \
  --left-expected-manifest-sha256 "$LEFT_SHA" \
  --right-expected-manifest-sha256 "$RIGHT_SHA"
```

只要完整历史里有一个 MOCK、缺原签、错根 SHA、目标文件变更或旧路径不可授权，都必须拒绝，不能把 EC337 `install-bundle` 的本地字节结果当作签名成功。真实历史旧路径作为签名消息字符串保留，读取映射仅限原 EC336 scoped ORIGINAL；不声称新目标**物理路径**就是旧签文字承诺的 OS/机构身份。

## 6. 正向结果、失败码和最终联合验收

- `exit 2 / unresolved`：归档创建、只读核对、安装字节核验或 EC336 验签分别只说明本次**本地已执行的对应动作**，不等于远程业务成功。`exit 3/4/5`：权限拒绝、非法输入或不可用；没有 `exit 0` 成功业务终态。
- **离线 ZIP 不加密**，需要受控离线介质或调用方外部加密传输。不得用它进行未经审批的数据出境。源/目标任意时间跨文件读取、输出写入与完整 readback 都不是不可变文件系统快照；文件置换的 OS 层最终一致性与跨机验证要由真实可信环境辅助。
- 最终由用户辅助：真实全无 mock EC294→337 材料、独立 custody 与签名角色/撤销、物理双机及 OS 权限、旧路径真实性解释、真实 signed readback/CAS/WORM/nonexecution/latest/winner、原 PowerShell7 Smoke15、跨 OS/Git/Provider/CI/E63–E66，逐项只认确实执行的结果。
