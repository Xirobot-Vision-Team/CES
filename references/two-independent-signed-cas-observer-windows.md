# EC312 操作协议：两名独立 Ed25519 observer 对同一批 CAS 已签裁决的原件窗口交叉对账

版本 **V6.22 / R312 / EC312**。新增内容仅是 **offline / read-only** 的原始签名证据重放与冲突分类；不替任何组织签署 CAS，不连接存储，不判断生产环境全球 latest，不修改旧的 EC294–311 证据格式。

## 1. 输入所代表的信任边界

操作员在工程包**之外**确定并另行记录一份私有规范 JSON manifest 的完整原字节 SHA256，将 `--expected-manifest-sha256` 作为外部输入，而不是从 manifest 自身、旧 PASS 报告或日志中读出它。所有原件均以**各自独立的外部原字节 SHA**绑定：EC307 真签 fork case、完整双分叉取证报告、EC308 Ed25519 CAS issuer 回执、observer A 的 EC309 Ed25519 回读、observer B 的另一份 EC309 Ed25519 回读。签署的 query nonce、issuer 前置 CAS `(revision, head)` 也分别由操作者显式钉住。

- 2～8 条**不同**的 EC308 issuer 已签裁决，按预期时间窗顺序放入 `decisions`，每条配齐**同一原始裁决**对应的两份原始 EC309 独立 observer 签名回读。每条裁决独立重验两遍原 EC309→EC308→EC307→…→EC294 的原始密码学签章，不能拿任何旧 EC311 或 EC309 计算结果充数。
- 正好两个 `observers`，按 `observer_id` 的**字典序**排列；两者 ID 与公钥必须不同，ID 不得与 issuer ID 相同，公钥与 issuer 及原 fork 中已知的 registrar / ACK / witness / receiver 密钥不同。签字密钥来自外部，程序不会加载私钥、调用签名服务或托管密钥。
- 两条独立 observer 窗口各有 `boundary`：`sequence=0` 时仅接受 `raw_sha256=000…000`、`observed_revision=null`、`observed_head_raw_sha256=null`；`sequence>0` 时另行 pin 完整前驱 readback raw SHA、之前 revision/head。**非 genesis 边界永远是未重放的包外 opaque 锚点**，不是其前史已经认证的断言。非 genesis 时，该边界中的 `(revision, head)` 还必须与本批第一份已签 issuer 的 CAS 前置条件吻合，否则报告父状态断链、无赢家。
- 每条 `readbacks` 有且仅有两项，按照同一字典序与 `observers` 精确对应；每份原件、查询 nonce、issuer 签名原件都不可跨本窗口重复。每个 observer 必须以自己的前驱 SHA/sequence/revision 精确连续；链上任何签名失真、错误文件 SHA、私有权限不满足、claim 不绑定原裁决或前驱，均 fail closed，不把破坏的签名记录当成合法冲突。

## 2. 私有 manifest 字段（严格白名单）

根对象必须恰含：

```json
{
  "schema": "ces.ec312.two_observer_signed_cas_window_manifest.v1",
  "cas_authority_id": "independent_cas_site",
  "cas_authority_public_hex": "<64 lowercase hex: independently trusted issuer public key>",
  "cas_store_namespace_id": "external_registry_namespace",
  "observers": [
    {
      "observer_id": "readback_independent_site",
      "observer_public_hex": "<64 lowercase hex: independently trusted A public key>",
      "boundary": {
        "sequence": 0,
        "raw_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "observed_revision": null,
        "observed_head_raw_sha256": null
      }
    },
    {
      "observer_id": "second_independent_site",
      "observer_public_hex": "<64 lowercase hex: independently trusted B public key>",
      "boundary": {
        "sequence": 0,
        "raw_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "observed_revision": null,
        "observed_head_raw_sha256": null
      }
    }
  ],
  "decisions": [
    {
      "fork_case_file": "/private/decision-1-fork-case.json",
      "expected_fork_case_sha256": "<independently verified 64 hex>",
      "fork_evidence_file": "/private/decision-1-fork-evidence.json",
      "expected_fork_evidence_sha256": "<independently verified 64 hex>",
      "receipt_file": "/private/decision-1-issuer-signed-receipt.json",
      "expected_receipt_sha256": "<independently verified 64 hex>",
      "expected_request_nonce_sha256": "<independently pinned issuer query nonce SHA>",
      "expected_parent_cas_revision": 27,
      "expected_parent_cas_head_sha256": "<independently pinned old CAS head SHA>",
      "readbacks": [
        {
          "observer_id": "readback_independent_site",
          "readback_file": "/private/decision-1-a-signed-readback.json",
          "expected_readback_sha256": "<independently verified A file SHA>",
          "expected_readback_request_nonce_sha256": "<independently pinned A query nonce SHA>"
        },
        {
          "observer_id": "second_independent_site",
          "readback_file": "/private/decision-1-b-signed-readback.json",
          "expected_readback_sha256": "<independently verified B file SHA>",
          "expected_readback_request_nonce_sha256": "<independently pinned B query nonce SHA>"
        }
      ]
    }
  ]
}
```

此处仅展示**第 1 条的字段模板**，尖括号是说明性占位符，**不是可执行示例**；实际 `decisions` 必须有 2～8 条，所有 SHA/nonce 必须是正好 64 个合法的小写十六进制字符，除允许的 genesis 外不可为 64 个 0，原件要实际存在于本机**绝对**私有路径中。原件与 manifest 必须是工具当前要求的 owner-private、严格 canonical JSON + `LF`，不能由调用者用未经证实的 PASS 标记替代。

原 EC309 Readback claim 中的：`observer_id`、`observer_public_hex`、`cas_store_namespace_id`、`readback_request_nonce_sha256`、原 EC308 receipt/cas claim SHA、fork/case SHA、issuer request nonce、`previous_readback_raw_sha256`、`previous_readback_observed_revision` 和 `readback_sequence`，均须与相应 pinned original 和之前**已重新验签**的原件完全一致。每名 observer 在每条裁决的序号必须比自己的上一条序号恰多一，不要求两个 observer 共享同一数字序号。

## 3. 双 observer 的新交叉规则

1. **共享**：两个 observer 的原件必须指向完全**同一份** EC308 issuer 签名 claim 和完全**同一份** EC307 fork case/evidence；整个时间窗固定 registry ID、CAS authority ID/public、namespace，两个 observer 身份/公钥各自固定。
2. **各自连续**：每条 observer 的前驱 SHA/seq/observed revision 与上一条自己经过验签的原件相等；真实已签 observed revision 下降记为 `signed_observer_window_revision_rollback`；单 observer 曾在相同 revision 签两个不同 head，记为 `signed_single_observer_same_revision_different_head`。
3. **交叉矛盾**：两个 observer 在**任意**窗口内分别对相同 revision 签署**不同** head，记为 `two_signed_observers_same_revision_different_head`，包括两个不同裁决索引中的交叉冲突；相同原裁决索引观察到**不同 revision** 仅记为 `two_signed_observers_on_same_decision_report_different_revisions`，不武断声称是同版冲突。
4. **跨裁决 parent**：后一个已签 issuer 的外部 `expected_parent_cas_revision` / `expected_parent_cas_head_sha256` 必须与前一份 **原已签 issuer** 的结果相同；两个 observer 前一条的已签 revision/head 也必须各自支持那个结果。任一失败标记 `two_observer_window_signed_cas_parent_discontinuity`。
5. **最终相容**：每份 issuer 必须是原 EC308 的已签 `compare_exchange_committed_claim`，两条 observer 都必须与 issuer 声明**完全同 revision/head**，全部关系无矛盾才能 `exit=0`。任何冲突、未知跨版本差异、前置失败或不相容均 `exit=2`，最后候选 SHA 必须为 `null`，不选胜者。完整 SHA/签名/角色/输入违约不是已签事实的冲突，返回严格拒绝。

冲突状态以 rollback、单 observer 同版异头、跨 observer 同版异头、issuer parent 断链、两 observer 版本分歧、issuer/observer 不互证的顺序优先显示，但**所有**异常列表都会记录在无路径报告中。对账依据只是一组离线签字人的**声明**，而非签名人与真实外部 CAS/WORM 同物理命名空间之间的真实性证明。

## 4. CLI / 审计回放

独立 CLI：

```sh
python3 scripts/ces_cas_observers.py verify \
  --manifest-file /absolute/owner-private/manifest.json \
  --expected-manifest-sha256 <independently-recorded-whole-raw-SHA256> \
  --out /absolute/new/owner-private-audit.json
```

省略 `--out` 可只读运行；可保存时使用原 `store.store` 的**新文件独占 O_EXCL / 0600 / fsync**，已存在文件一律拒绝覆盖。独立审核者拿到**第二个包外 pin 的完整报告 SHA**，用下列命令重新跑**所有原始 Ed25519 签章**并逐字段比较整个规范审计报告（不能只读结果摘要）：

```sh
python3 scripts/ces_cas_observers.py verify-report \
  --manifest-file /absolute/owner-private/manifest.json \
  --expected-manifest-sha256 <whole-manifest-raw-SHA256> \
  --audit-report-file /absolute/owner-private-audit.json \
  --expected-audit-report-sha256 <separately-recorded-report-raw-SHA256>
```

统一控制台为**更小权限**的只读入口：

```sh
python3 scripts/ces_next.py audit-observers \
  DeliveryAudit ReconcileTwoSignedCasObservers \
  --manifest-file /absolute/owner-private/manifest.json \
  --expected-manifest-sha256 <whole-manifest-raw-SHA256>
```

控制台只会用固定 `-I -B` 隔离子进程执行 `verify`；不会向子进程透传 `--out`、私钥、CAS/Host grant、任意 API endpoint，也不授权新旧 router 或原生 PowerShell 写操作。结果状态/计数/非过度声称布尔值须与子进程返回码相容，否则控制台拒绝。

`exit=0`：所提供有界窗口内的原签 issuer 和两条不同的 observer 的签名声明均相容；`exit=2`：存在真实已验签矛盾/不相容而无赢家；`exit=3`：权限、签名或证据不符合信任边界；`exit=4`：显式参数/结构非法；`exit=5`：材料或本机环境不可用。`argparse` 的命令行语法错误也可能在模块外以代码 2 退出，并非一条已签业务冲突。

## 5. 严格未验证清单

本机新功能性测试使用模拟 Ed25519 issuer/observer 密钥和真实签署的 fixture，能验证**原签章重放、SHA pin 和代码判别**；不能证明真实第三方组织分别授权、密钥互不托管/被撤销、nonce 不重复的全球性、可信顺序/时间、同物理存储、CAS 原子线性化、多地事务和真 WORM、窗口外任何遗漏并发写/观察、全网最新记录、原历史物理 ZIP/ACK 托管、NFS/恶意竞态/断电恢复、生产 Provider/Inbox、Windows/macOS、PowerShell7 旧 15 smoke、Git/CI/E63–E66 或最终联合验收。EC249 / EC250 / B001 / global Quality 的既有阻断不变。
