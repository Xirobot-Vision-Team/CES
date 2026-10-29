# EC331 离线报告集合交叉引用：输入、信任边界与可重演语义

## 1. 功能总览

`construction/ec331_offline_report_set_crosscheck/crosscheck.py` 只对 2–8 份 EC330 不可自证公信力的**无签原报告**，经完整旧原签名真重演后作本地有限集合交叉对照。**输入整个 manifest 原 SHA 必须事先由真实可信包外渠道保管/交付**；提供 `--expected-manifest-sha256` 字符串只是向程序声称该可信渠道存在，并不能自我证明可信来源。每条比较记录中必须放入真正另受信的 old source whole SHA、身份、挑战、原路径；**绝不从报告里的 claim 字段直接复用为 trusted expected**。无签 manifest 不会自行授予 CAS/机构写操作权限。

## 2. 精确输入结构

Manifest 必须以 owner-private `0600` 的独立规范 LF JSON 存放，字节数最多 140,000。对象字段仅为 `schema` 与 `reports`，`reports` 为 2–8 项；每项字段严格为：`report_file`，`expected_report_sha256`，`comparison_inputs`。不同项的 `report_file` 必须是不同的规范绝对路径，允许其 whole raw SHA 相同（表明原字节相同、需去重）；报告路径不得别名 manifest 或任何签名原材料路径；不接受 `/../`、symlink、不私有的输入原件。

示例（**只展示形状，SHA 与真实认证材料必须由你自己的受信包外渠道提供，不能从本示例凭空生成**）：

```json
{
  "schema": "ces.ec331.externally_pinned_offline_report_set_manifest.v1",
  "reports": [
    {
      "report_file": "/private/evidence/report-A.json",
      "expected_report_sha256": "<64-lowercase-hex-obtained-independently>",
      "comparison_inputs": {
        "branch_a_ledger_file": "/private/evidence/ledger-A1.json",
        "expected_branch_a_ledger_sha256": "<trusted-sha>",
        "branch_b_ledger_file": "/private/evidence/ledger-A2.json",
        "expected_branch_b_ledger_sha256": "<trusted-sha>",
        "branch_a_prior_ledger_file": null,
        "expected_branch_a_prior_ledger_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "branch_b_prior_ledger_file": "/private/evidence/ledger-A1.json",
        "expected_branch_b_prior_ledger_sha256": "<trusted-sha>",
        "request_file": "/private/evidence/signed-eighth-request.json",
        "expected_request_sha256": "<trusted-sha>",
        "case_file": "/private/evidence/dispute-case.json",
        "expected_case_sha256": "<trusted-sha>",
        "registry_id": "<trusted-registry-id>",
        "expected_sequence": 1,
        "expected_prior_registry_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "request_id": "<trusted-request-id>",
        "target_store_namespace_id": "<trusted-namespace>",
        "eighth_signer_id": "<trusted-id>",
        "eighth_signer_public_hex": "<trusted-public-hex>",
        "request_challenge_sha256": "<trusted-challenge-sha>",
        "left": {
          "registry_file": "/private/evidence/left-original.json",
          "expected_registry_sha256": "<trusted-sha>",
          "capsule_file": "/private/evidence/left-capsule.zip",
          "origin_file": "/private/evidence/left-origin.json",
          "expected_origin_sha256": "<trusted-sha>",
          "recipient_file": "/private/evidence/left-recipient.json",
          "expected_recipient_sha256": "<trusted-sha>"
        },
        "right": {
          "registry_file": "/private/evidence/right-original.json",
          "expected_registry_sha256": "<trusted-sha>",
          "capsule_file": "/private/evidence/right-capsule.zip",
          "origin_file": "/private/evidence/right-origin.json",
          "expected_origin_sha256": "<trusted-sha>",
          "recipient_file": "/private/evidence/right-recipient.json",
          "expected_recipient_sha256": "<trusted-sha>"
        }
      }
    },
    {"report_file": "/private/evidence/report-B.json", "expected_report_sha256": "<trusted-sha>", "comparison_inputs": {"...": "同样全部 EC330 已验入参，不允许省略必填字段"}}
  ]
}
```

上面的 `"<...>"` 和第二条 `"..."` 只是形状说明，**并非可运行的合法 manifest**。实际严格的全部可选/必选字段见 `construction/ec331_offline_report_set_crosscheck/crosscheck.py` 中 `REQUIRED_COMPARE_KEYS/OPTIONAL_COMPARE_KEYS`，语义对应既有 `scripts/ces_cas_review_report.py verify-report` 的完整参数。`prior_registry_file` 可为 `null`（genesis），两个前置账本 path 和 SHA 必须按实际源存在性成对提供；`comparison_inputs` 不能包含 `--out`、私钥、host endpoint、CAS auth 或未知参数。第九身份材料仍需要通过真实旧 EC328/327 受信原签材料验证，不能只看本 schema。

从**真正已核实可信的各字段**构造 Python `dict` 后，用下列本地步骤形成规范字节（这**不**取代真实包外独立保管）:

```python
from ec324_dual_channel_receipt import receipt
receipt._write_exclusive('/private/evidence/ec331-manifest.json', receipt._raw(manifest_dict))
```

必须在**另一个真实可信渠道**冻结并交付整份 manifest 原字节的 SHA256，然后只读验证：

```bash
python3 -I -B scripts/ces_cas_report_set.py compare-report-set \
  --manifest-file /private/evidence/ec331-manifest.json \
  --expected-manifest-sha256 YOUR_INDEPENDENTLY_TRUSTED_MANIFEST_RAW_SHA256

python3 scripts/ces_next.py audit-hold-report-set \
  DeliveryAudit CompareOfflinePinnedReportSet \
  --manifest-file /private/evidence/ec331-manifest.json \
  --expected-manifest-sha256 YOUR_INDEPENDENTLY_TRUSTED_MANIFEST_RAW_SHA256
```

## 3. 处理与结果的精确含义

1. 先严格核对整份 manifest 原 SHA、`0600`、规范 LF JSON、2–8 条形状、全部路径互不假冒签名材料。长度不符或某条缺完整旧受信信息直接拒绝。
2. 对每一条真正调用 `ec330_replayable_comparison_report.report.verify_report`；它进一步真正调用 EC329 两原 EC328 签名账本、旧 EC327/326/325/294 完整原签名验证和二次报告逐字节核对。任何一条出现旧真签、SHA、源路径或 schema 无效即整体 `3/4/5` 拒绝。
3. 再检查本次集合内全部旧第八请求上下文一致，得到最多 16 个去重原账本节点/最多 120 个节点对。已验证的原 immediate predecessor + 恰好一行的严格追加才算可证的本地直接边；只有共同条目前缀不证明缺失的中间原件、可信排序或远端 latest。
4. 同一第九真实签名原 whole SHA 跨报告按一份计数；不同原 SHA 复用 `ninth_responder_id`、`ninth_responder_public_hex`、`response_challenge_sha256`、`decision_id`、`receipt_file` 逐字段分组。额外标出哪些冲突只在跨报告组合可见；身份/路径仅输出经域分离 hash 指纹，避免直接暴露本地绝对路径。相同签名原字节复制到不同本地原路径不算新票。
5. 完成关联后，重新 `receipt._load` 核对全部 2–8 份 EC330 whole SHA；再经原生产方法逐份重查两账本、前账本、第九签名、第八请求、争议案卷及旧双边所有源原 SHA；最后重新核对 whole manifest 原字节。
6. 返回 `schema=ces.ec331.offline_report_set_cross_reference.v1`、`exit_code=2`、枚举的 `verified_local_ledger_nodes`、`ledger_pair_relationships`、跨报告追加/同父/相同签名/角色冲突分类和全部禁止“远端成功”的显式 `false`。新报告集结果**只存在控制台输出，不生成签名或有权威性的原文件**；没有网络、外部 CAS/本地写/私钥/API 副作用。

## 4. 原生产包外待验

**局部测试 16/16** 是真第八/第九 Ed25519 + 继承 EC321 原 EC317/318 深层 structural mock 的有限 fixture。真正隔离 `-I -B` 对 mock 已签旧历史必须 fail-closed，而不是给出 `exit2`。在真实物理外部 SHA custody、非 mock EC294→331 全链真原件、OS/PS7/Provider/CI/CAS/WORM、组织授权和用户集中验收前，所有较强承诺必须保持 `NOT_PROVEN`。局部双报告一致、双报告分叉或离线「未执行」签署意见不建立 global latest、实际未执行、赢家、远端可线性化写入或机构真实性。
