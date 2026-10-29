# EC176 本地合成功能场景（非最终联验）

运行：`cd ces/construction && python -m unittest -v test_codesave_staged`。

这些测试复用 EC170 构造器、EC171 真实内存 Run/Handoff、EC172 原子私有 checkpoint、EC173 HMAC 私有输入、EC174 本地构造的回调、EC175 本地**合成签字**，在临时 owner-only POSIX 目录中实际创建全新的 EC176 私有保存根，执行授权后无覆盖元数据写入与 HMAC 读取。确认不向测试业务仓写任何字节，不向 store 存储原始代码、路径、AI finding 文本或 review note，且拒绝 EC175 无秘钥摘要冒充写入令牌。

聚焦场景覆盖：单次真正写入/读取与 SHA/HMAC；输入/私有存储根不重叠；独立写/读/签字/目标 pin/operation 许可；原结果伪造与源草稿/候选/修订漂移；无签字、伪造签字、驳回/不确定、不同源范围；在锁内二次重新检验；相同 operation 幂等且 TTL 不延长、不同 operation 重复候选拒绝；记录篡改/硬链接/未知 entry/残留 pending/目录权限；时效、部分coverage与历史 ProposedPR 限定；只含元数据的本地管理 CLI。

**这些用例没有连接实际模型、人工审核者、业务 Git/CI 或远端 Provider。** 合成 fixture key 只用于代码路径检查，不能在实际环境中使用。原 PowerShell7/15 Smoke、跨OS/cross-process恶意竞争/真断电、外部秘钥的独立可信托管、E63–E66性能、EC177+及最终联验均 `NOT_RUN`。
