# EC302：离线完整 EC301 签名证据 ZIP 的导出、核验、移机导入

适用：当前完整施工包 `V6.12/R302`，带完整的 EC301 `journal-file`、两位独立外部见证公钥/身份及其最新 4 个 SHA 的**本地 POSIX/Linux** 环境。只处理只读的已签审计证明；不提交业务、不触达 Provider/Inbox，不自动发送电子邮件/网络、不读取私钥。真正跨站、权限、传输介质、密钥保存与终验需组织自行执行。

## 准备：先独立保存四个不可由包内自动发现的最新 SHA

每位发送/接收操作员都要独立得到如下 8 个值（**不要用收到的 ZIP manifest 反向确定所谓可信值**）：

```bash
# 示例中的值仅是占位符，必须替换为真正外部渠道确认的值。
A_ID='...'; A_PUB='...'; A_TIP='...'
B_ID='...'; B_PUB='...'; B_TIP='...'
SESSION_TIP='...'; RECEIPT_TIP='...'
COMMON=(
  --expected-a-id "$A_ID" --expected-a-public-hex "$A_PUB" --expected-a-tip "$A_TIP"
  --expected-b-id "$B_ID" --expected-b-public-hex "$B_PUB" --expected-b-tip "$B_TIP"
  --expected-session-tip "$SESSION_TIP" --expected-receipt-tip "$RECEIPT_TIP"
)
mkdir -p -m 700 "$HOME/ces-private"
# 请将路径换成当前设备上的绝对路径，不支持覆盖旧目录和输出文件。
```

## 发送侧：导出经全链核验的真正来源文件

```bash
python3 scripts/ces_evidence_bundle.py export \
  --journal-file "/absolute/path/to/ec301-complete-journal.json" \
  "${COMMON[@]}" --out "$HOME/ces-private/ec301-evidence.zip"
```

导出先真实重验全部 EC301/EC300/EC299/EC297 签名与更早原始审计，再收集**仅**协议固定的证明引用和文件，转换旧绝对路径并构建新私有快照重新重验。JSON 返回整 ZIP `bundle_sha256`、`manifest_sha256`、源审计 `report_sha256`、`evidence_document_count` 和历史状态，完整 `bundle_sha256` 必须与八个见证信任参数**在另外独立可信渠道**传给接收者；不要依赖包内文字自动取 SHA。建议保密传输介质、对真实证据进行数据分级/加密。ZIP 本身**未加密**，只读公开签名证据也可能包含业务任务标识。

## 接收侧：先验证再持久导入

```bash
# 将人工转移的 ZIP 放到接收方 $HOME/ces-private，确保仅自己能读：
chmod 600 "$HOME/ces-private/ec301-evidence.zip"
# 与收到的包内容分开的可信渠道确认：
EXTERNAL_ZIP_SHA='...'  # 真正 64 位小写 hex

# A/B/SESSION/RECEIPT 8 个变量须重新从独立保管记录加载；
# 首先无业务作用地在私有临时目录完成完整验证。
python3 scripts/ces_evidence_bundle.py verify \
  --bundle-file "$HOME/ces-private/ec301-evidence.zip" \
  --expected-bundle-sha256 "$EXTERNAL_ZIP_SHA" "${COMMON[@]}"

# 只有前一步通过才在一个此前不存在的私有目录完成持久导入：
python3 scripts/ces_evidence_bundle.py import \
  --bundle-file "$HOME/ces-private/ec301-evidence.zip" \
  --expected-bundle-sha256 "$EXTERNAL_ZIP_SHA" "${COMMON[@]}" \
  --dest-dir "$HOME/ces-private/received-ec301"
```

`import` 返回的 `rebound_journal_file` 应为形如 `/home/operator/ces-private/received-ec301/docs/0001.json` 的**本机绝对路径**。可直接交给旧 `scripts/ces_anchor_handoff.py verify-journal` 继续审计。原始 EC295 policy 是原始**字节 SHA**，必须保留 raw bytes；旧 signed receipt、rotation bridge 等源文件签名原样不变，只有中转用的绝对文件路径被重新指向新的私有目录。对 ZIP 重放旧历史不会自动发现缺失的全网最新记录；仍必须信任独立的四 SHA pin 及外部 ZIP raw SHA。

如要通过统一控制台做**只读核验**，可运行：

```bash
python3 scripts/ces_next.py audit-bundle DeliveryAudit VerifyPortableBundle \
  --bundle-file "$HOME/ces-private/ec301-evidence.zip" \
  --expected-bundle-sha256 "$EXTERNAL_ZIP_SHA" "${COMMON[@]}"
```

## 结果代码和限制

- `0`：收到且外部指定的**这套**证明链复验通过，未在本套材料中发现签名竞争/不确定；**不**证明全球最新、实际已交付或组织签字人独立。
- `2`：全部签名/引用校验完成，但已签历史中有**真实竞争证据或无法判明的历史**；不得强行改成 PASS。
- `3/4/5`：拒绝输入/权限约束失败/本地环境不可用。导出或导入不得被静默改为成功；若中途 IO 失败，私有目标目录可能保留不完整证据，必须人工调查后选一个**新**目录重做。

底层仅接受 11 类协议 JSON、最多 2048 份文档、未压缩 ZIP 总量 ≤24MB、净证据 ≤22MB；严格拒绝旧机器绝对路径泄漏、路径逃逸、额外 Zip 条目、symlink、异常 key 内容。`export` 与 `import` 的目标 parent 必须由当前用户持有且模式 `0700`；ZIP 须 `0600`，文件的 `fsync`/目录 `fsync` 不等于断电实测。跨 Windows/macOS、共享盘/NFS 原子性、独立传输验证、密钥/组织吊销/可信时间/远端 WORM、真实 Provider/Inbox、原生 PS7 15 Smoke 和最终联合验收**本轮未测**。

**当前未闭合**：EC249 `FULL_FUNCTION_NOT_COMPLETE`；EC250 `BLOCKED`；B001 `OPEN`；全局 Quality PASS=false；final `NOT_STARTED`。
