# EC303 操作指南：接收方本地重验后签署离线 ZIP 收据，原发送方离线核验

**版本：`V6.13 / R303`。** 前提：已依照 [EC302](ec302-portable-ec301-evidence-bundle.md) 在接收设备**新的 owner 0700 私有目录** `import` 完整原 EC301 签名证据 ZIP，并从接收方的**独立可信渠道**取得原 ZIP raw SHA 和 8 个旧 witness 信任字段（A/B 身份、公钥、各自最新观察 SHA、最新 session SHA、最新 EC301 receipt SHA）。**不可**从 ZIP manifest 自行推定所谓最新权威值。

## 1. 发送方离线生成一个本次专用的挑战，独立保存

由源端独立制作一个本次交换专用的随机挑战 SHA，记录“发送方/接收方 ID + ZIP SHA + 8 个旧 pin + challenge SHA”；接收方只使用来自这个独立传递渠道的摘要，不信任 ZIP/未签留言自称的挑战。下例的本地随机数生成演示不代表外部 WORM/不可重放治理：

```bash
CHALLENGE_SHA="$(python3 -c 'import secrets,hashlib;print(hashlib.sha256(secrets.token_bytes(32)).hexdigest())')"
# 把这份 challenge SHA 通过独立渠道告知接收方，绝不能为下次不同交换复用。
```

各方分别独立准备原 EC302 `COMMON` 参数；具体说明请读上一轮 runbook。

```bash
COMMON=(
  --expected-a-id "$A_ID" --expected-a-public-hex "$A_PUB" --expected-a-tip "$A_TIP"
  --expected-b-id "$B_ID" --expected-b-public-hex "$B_PUB" --expected-b-tip "$B_TIP"
  --expected-session-tip "$SESSION_TIP" --expected-receipt-tip "$RECEIPT_TIP"
)
ZIP='/absolute/private/path/received-evidence.zip'
ZIP_SHA='...'       # 包外独立保存的原 ZIP raw 字节 SHA256
SRC_ID='source-01'; DEST_ID='destination-02'
```

## 2. 接收方用额外的、不同于两把 witness 的独立 Ed25519 密钥签收

接收方需自有的 raw Ed25519 32 字节私钥（不是 PEM，不是 witness A/B 共用钥匙）；本示例仅在私有目录里演示生成，不是生产 HSM/人员独立性的证明。

```bash
mkdir -p -m 700 "$HOME/ces-private"
python3 - <<'PY'
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
folder = Path.home() / 'ces-private'
path = folder / 'receiver-ed25519.key'
fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, 'wb') as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()))
    f.flush(); os.fsync(f.fileno())
print('RECEIVER_PUB='+key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw).hex())
PY
```

接收方公钥 `RECEIVER_PUB` 必须从可信的接收者身份渠道与发送方单独确认，**不要**直接相信收到的回执或命令回显。`received-ec301` 必须是上一轮 EC302 import 成功后已有的**原样私有目录**，签回 JSON 放在它的**外面**：

```bash
RECEIVER_PUB='...'              # 由独立渠道确认，必须不同于 A_PUB/B_PUB
python3 scripts/ces_bundle_ack.py issue \
  --bundle-file "$ZIP" --expected-bundle-sha256 "$ZIP_SHA" "${COMMON[@]}" \
  --expected-sender-id "$SRC_ID" --expected-receiver-id "$DEST_ID" \
  --expected-receiver-public-hex "$RECEIVER_PUB" \
  --expected-exchange-challenge-sha256 "$CHALLENGE_SHA" \
  --imported-dir "$HOME/ces-private/received-ec301" \
  --receiver-private-key-file "$HOME/ces-private/receiver-ed25519.key" \
  --out "$HOME/ces-private/ec303-receiver-ack.json"
```

若历史存在已观察真实签章冲突、不确定，或从 ZIP 到本地 docs 任意一份证据已变、目录有额外文件/不符合 0700/0600 或公钥不是第三把独立接收者密钥，**不会签发成功收据**。签发返回 `acknowledgement_sha256` 是带末尾 LF 的整份**原始文件字节 SHA**，与旧 `EC301 receipt_tip` 不是同一种信任值。仅人工将已签收据副本移交源端，**独立渠道**保存 SHA / 公钥 / challenge，不要把回执原文件当成外部可信来源。

## 3. 源端独立验收收到的签名与完整原始证明

发送方必须从外部独立记录取得 `RECEIVER_PUB`、本次 `CHALLENGE_SHA`、原 `ZIP_SHA` 和 8 个旧 pin，还须有独立保管的**完整原回执 raw SHA**；不能从收到的回执自身提取这些值作为可信输入。

```bash
ACK='/absolute/private/path/ec303-receiver-ack.json'
ACK_SHA='...'   # 独立记录的本回执完整文件 raw SHA，不从回执字段信任其值
python3 scripts/ces_bundle_ack.py verify \
  --bundle-file "$ZIP" --expected-bundle-sha256 "$ZIP_SHA" "${COMMON[@]}" \
  --expected-sender-id "$SRC_ID" --expected-receiver-id "$DEST_ID" \
  --expected-receiver-public-hex "$RECEIVER_PUB" \
  --expected-exchange-challenge-sha256 "$CHALLENGE_SHA" \
  --acknowledgement-file "$ACK" --expected-acknowledgement-sha256 "$ACK_SHA"

# 对外可暴露的统一控制台只允许做完全相同的只读核验：
python3 scripts/ces_next.py audit-ack DeliveryAudit VerifyBundleAcknowledgement \
  --bundle-file "$ZIP" --expected-bundle-sha256 "$ZIP_SHA" "${COMMON[@]}" \
  --expected-sender-id "$SRC_ID" --expected-receiver-id "$DEST_ID" \
  --expected-receiver-public-hex "$RECEIVER_PUB" \
  --expected-exchange-challenge-sha256 "$CHALLENGE_SHA" \
  --acknowledgement-file "$ACK" --expected-acknowledgement-sha256 "$ACK_SHA"
```

`verify` 先核对整份原回执 raw SHA、严格 JSON 字节规范与接收者 Ed25519 签名，再重新验真实 ZIP 和所有原 EC301→EC294 原始签章，并要求签名 claim 与从这些**独立外部 pins**推导的值完全相同。源端无须获取接收方私钥或其本机绝对导入路径。统一控制台绝不开放 `issue` 或 private key 参数；原业务 Router 权限仍全部不变。

## 4. 结果和不能宣称的事项

`0` 只代表：**这组具体外部指定的** ZIP SHA、四 tip、双方 ID、公钥与 challenge 相容，且真实来源签章已重新校验，接收者私钥签署了指定声明。`3/4/5` 是明确拒绝或环境不可用，**不是已签收**。如果原 EC302 检查得到签章历史竞争或不确定（其旧命令返回 `2`），EC303 **拒绝签发正向 ACK**，不通过新签字粉饰旧风险。

签章/收据并**不能**证明真实不同设备、真人独立、安全物理传输、可信/不可重放的挑战管理、密钥撤销、导入后的持久 WORM 防回滚、可信 UTC、未观察的历史分叉、生产 Provider/Inbox 成功。生成和验证需在支持 POSIX 私有目录/原子文件权限的主机上人工验证实际效果；原生 PS7、Windows/macOS、断电/NFS、E63–E66、CI/Git、EC249/250/B001 与最终联合验收仍未执行。
