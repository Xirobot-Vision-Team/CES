# EC334 一跳原件路径映射、跨机 whole-SHA 字节保全预检协议

## 目标：让接收者知道“复制的哪些字节等于原件”，而不是伪造跨机原签认可

这是严格区分 **源端真实已签历史回放后** 的无签 inventory 候选，以及 **目标端只读复制完整性** 的两个阶段。旧 EC331、EC328 原绝对路径及签名输入不改；源端生成 inventory 必须执行 EC333 `verify_handoff` → EC332 → EC294 生产原签重演。接收端只有 inventory/map 的 SHA 容器绑定，不再调用原签历史验签，因此不能把跨路径 byte-match 等同于历史身份与签名认可。

## 不可改变的三个文件角色

| 文件 | 限制 | 真实用途 |
|---|---|---|
| EC333 handoff、EC331 双 manifest | 三份由源端使用者**另外可信**固定的原 whole SHA | 源端先完整 replay，禁止清单从缓存结果生成 |
| `ces.ec334.first_hop_private_unsigned_relocation_inventory.v1` | canonical sorted ASCII LF JSON、`0600`、私有归属/单硬链接、<=950KB、<=1024 源原件 | 源绝对路径、raw SHA、字节长度、按字典序去重来源角色、SHA 来源层次；无签、本机文件路径敏感 |
| `ces.ec334.explicit_private_source_to_destination_map.v1` | canonical LF JSON、`0600`、<=550KB，exact source paths sorted + unique destination paths | 将已经 pinned 的每个源绝对路径映到一个明确的目标绝对路径；不含或提供可冒充的源 SHA 新值 |

两份新文件须由接收人通过**真实独立渠道**分别得到各自的 whole raw SHA，并从受控介质获得其未改写原字节。新清单只校验**直接引用**原件，包括 EC331 报告/EC328 账本/其第九签名回执及 EC330 比较直接材料。EC317/EC318 等间接原材料**不在本项直接闭包保证内**。

### inventory source record schema

```json
{
  "source_path": "/source/evidence/raw.json",
  "source_original_raw_sha256": "<64 lower hex chars>",
  "byte_length": 12345,
  "pin_basis": "existing_signed_history_input_or_ledger_sha",
  "roles": ["ec330_report"]
}
```

`pin_basis=measured_after_full_source_replay_only` 适用于没有 EC331 直接 whole SHA 的 capsule：仅在源端旧真实签材料已通过回放后从私有原文件实际读取 SHA；没有另外的签名结论。对于重复同一路径，角色合并且必须同样原字节；相同 SHA 的不同物理文件允许存在但不算额外签署意见。

### 映射示例

```json
{
  "schema": "ces.ec334.explicit_private_source_to_destination_map.v1",
  "inventory_original_raw_sha256": "<independently entrusted inventory whole raw SHA>",
  "locations": [
    {
      "source_path": "/source/evidence/raw.json",
      "destination_path": "/receiver/private/evidence/evidence/raw.json"
    }
  ]
}
```

实际必须包括 **inventory 的全部 1–1024 条路径**（本项目至少有 handoff + 双 manifest），按原有 source_path 排序，不能缺失/插入/重排，destination_path 必须规范绝对且互不重复，不得与计划/映射文件别名或与另一条源路径产生身份混淆。至少有一条源目标不同。`prepare-map` 只做固定根前缀替换，要求所有源文件严格处于 source_root 子树，拒绝 `..` 逃逸；不同机器可自行经受信途径生成规范 map 文档，`verify-copies` 只以独立 whole SHA 验证收到的 map。

## 原件真实性与权限控制

- 所有源端实际文件、目标文件、清单/映射文件必须由当前归属用户持有，常规文件 `0600`、单硬链接、无 symlink，父目录符合原项目私有原件访问边界；沿用 `ec319._private_read` 而非普通 `open` 读取未经验证路径。
- 每个原始字节 SHA 和大小都核对，两遍核对目标 files；最后再次独立核对 plan/map SHA。读后重复 SHA 只是有限可观测检查，**不证明事务原子隔离/ABA 不可能**。
- 单原件最多 110MB、所有不同源路径累计最大 192MB、最多 1,024 条，拒绝超界，且未枚举不等于不存在。
- `create-plan` 显式 standalone writer；`prepare-map` 显式 standalone writer；统一 `audit-relocation-copies DeliveryAudit VerifyRelocatedFirstHopSourceCopies` 只有固定 `-I -B verify-copies` 的已限权读，拒绝任何签名、出网/远端、映射写入。
- JSON 中存原/目标**完整绝对路径**，可能是敏感基础设施细节，务必仅在私有目录和受控渠道流转。成功 stdout 不打印这些路径。

## 出口含义

`exit2` = 首层复制原件 SHA 匹配 *本地离线未决*；`exit3` 权限拒绝，`exit4` 非法输入/损坏，`exit5` 缺环境/读失败。统一入口还二次检查全部 `FALSE_FIELDS` 必须为 false，拒绝 child `exit0` 伪成功。`destination_bytes_match_every_first_hop_original=true` 只证明此次观测的全部显式原始文件长度+SHA 匹配；`destination_replay_of_full_ec294_to_ec333_original_signatures_performed=false`、`first_hop_inventory_proves_all_nested_historical_originals_present=false` 永远不改变。

## 后续与用户协助终验边界

若需要真正异构机器的完整 EC333 验签，必须另行明确重绑定原绝对路径、域分离 local path 指纹、签名消息原 SHA、EC317/318 间接闭包与可信路径引用的协议；不能简单替换 manifest 字符串或者用新路径的读回 SHA 声称复验已成功。真实独立 SHA 保管、真实物理设备、全旧无 mock 原签、原 PS7 Smoke15、Provider/CI、最终真实 remote CAS/WORM/nonexecution/latest/winner 均待用户最终联合核验。
