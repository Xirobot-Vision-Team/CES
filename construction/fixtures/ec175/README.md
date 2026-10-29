# EC175 开发用本地合成场景（非产品验收）

运行入口：`cd ces/construction && python -m unittest -v test_codevalidate_staged`。用临时 POSIX owner-only CES 根、假的业务仓单个只读文件、EC170 合成来源、EC171 实际创建的Run/Handoff、EC172真实本机HMAC暂存、EC173真实不可变输入与EC174本地假callback返回，测试新增CodeValidate本地校核和拒绝。**fixture 的 Provider/模型与受信人工审核签字都是本地构造字节**，没有连接网络、外部密钥、真实AI、真人、Git/CI或真实测试命令。

新增关注点：`schema_only`不能当草稿，`partial/2`和SHA不能做自动保存授权；独立验证/读取/历史来源授权；exact RunId/HandoffId/revision/event/operation key 和 source identity/context/evidence/material SHA；草稿摘要和正文不允许编辑；patch与非patch锚点位置、行号、完整引用、anchor SHA重验；Provider或模型声称已验证拒绝；HMAC stage/input和source/TTL前后重查；独立人工 reviewer 配置/HMAC/逐Finding判定和有效时间；对历史ProposedPR/DeliveredTarget的隔离；任何分支均不改业务源或CES store；CLI不打印源码。

未验证项累计：真 Provider 身份、真人/设备管理的 reviewer key、实际缺陷语义/人工复核内容、真实 Git SHA/CI执行、PowerShell7/15 Smoke、真实同UID进程对抗与OS/FS/断电、E63–E66性能、跨 EC176+全链和最终人工集中验收。不能用合成场景中的签名来宣布真实CI PASS或真实缺陷已修复。
