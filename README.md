# AI-QUIC

`AI-QUIC` 是一个面向学习和分阶段实现的 QUIC 协议实验仓库。当前代码已经完成阶段 0 和阶段 1：除 QUIC v1/v2 的报文解析、Initial 密钥派生、Initial 报文保护/解保护、传输参数处理、最小化 ACK 与在途包管理外，还补上了基于 BoringSSL 的 TLS 1.3 QUIC 回调层、CRYPTO 数据重组、transport parameters 注入与解析、Handshake/1-RTT 密钥安装，以及 Initial/Handshake 旧密钥丢弃。项目仍然不是完整的 QUIC 协议栈，更接近“协议构件验证平台”。

## 参考标准

本仓库的功能审计基线主要参照以下 RFC：

- RFC 9000, *QUIC: A UDP-Based Multiplexed and Secure Transport*, 2021-05
- RFC 9001, *Using TLS to Secure QUIC*, 2021-05
- RFC 9002, *QUIC Loss Detection and Congestion Control*, 2021-05
- RFC 9369, *QUIC Version 2*, 2023-05


## 项目结构

- `include/`: 协议接口与数据结构定义
- `src/packet/`: 包头、版本、Retry、传输参数、Initial 包和包保护实现
- `src/crypto/`: Initial 密钥派生
- `src/tls/`: BoringSSL QUIC/TLS 适配层与握手驱动
- `src/frame/`: 帧级别的通用语法解析
- `src/recovery/`: ACK 解析与最小在途包管理
- `src/transport/`: UDP 批量接收、连接骨架与 CRYPTO 缓冲
- `example/`: 基于 UDP 的最小 QUIC server/client 示例
- `tests/`: 分阶段测试

## 技术简介

当前实现采用“先做可验证协议部件，再串联最小接收路径”的方式组织：

1. 先在 `pkt_decode.c`、`quic_version.c` 中完成 QUIC 长/短头预解析和 v1/v2 版本分派。
2. 在 `quic_crypto.c` 中根据 RFC 9001 与 RFC 9369 的 Initial salt、HKDF label 派生 v1/v2 Initial 密钥。
3. 在 `quic_packet_protection.c` 中实现 AES-128-GCM 载荷保护和 AES-ECB 头部保护，用 RFC 向量验证。
4. 在 `quic_initial.c` 与 `quic_connection.c` 中构造最小 Initial 接收路径：解析头部、解保护、遍历帧、抽取 CRYPTO/ACK 信息。
5. 在 `quic_transport_params.c`、`quic_retry.c`、`quic_ack.c` 中实现若干独立协议构件，方便单独测试。
6. 在阶段 0 中将连接层重构为统一骨架：引入连接状态机、三类包号空间、统一收包分发、统一发包计划入口，以及统一定时器/事件处理接口。
7. 在阶段 1 中接入 BoringSSL 的 `SSL_QUIC_METHOD`，实现 CRYPTO 数据重组、transport parameters 注入/解析、Handshake 与 1-RTT 密钥安装、握手 flight 定时重传，以及最小化的短头包 PING 验证路径。

## 功能审计结果

### 已实现功能

以下功能已有代码实现，且当前仓库中均有对应测试覆盖。

| 模块 | 已实现能力 | 对照 RFC | 主要文件 | 对应测试 |
| --- | --- | --- | --- | --- |
| 包头预解析 | 解析 Long Header / Short Header 的固定比特、版本、DCID、SCID | RFC 9000 | `src/packet/pkt_decode.c` | `tests/test_phase1.c` |
| UDP 接收骨架 | `recvmmsg`/`recvmsg` 批量接收、预解析、有效包计数 | RFC 9000 | `src/transport/udp_io.c` | `tests/test_phase1.c` |
| 版本路由 | QUIC v1/v2 版本识别、长头包类型映射 | RFC 9000, RFC 9369 | `src/packet/quic_version.c` | `tests/test_phase2.c` |
| 版本协商生成 | 生成 Version Negotiation 包 | RFC 9000 | `src/packet/quic_version.c` | `tests/test_phase2.c` |
| Initial 密钥派生 | v1/v2 Initial secret、key、iv、hp 派生 | RFC 9001, RFC 9369 | `src/crypto/quic_crypto.c` | `tests/test_phase3.c` |
| QUIC varint | 变长整数解码、编码、长度计算 | RFC 9000 | `src/packet/quic_varint.c` | `tests/test_phase4.c`, `tests/test_phase6.c` |
| 帧语法解析 | 对多类传输帧做语法级遍历与跳过 | RFC 9000 | `src/frame/frame_decode.c` | `tests/test_phase4.c`, `tests/test_phase6.c` |
| 传输参数编解码 | 编解码常见 transport parameters 与 version_information | RFC 9000, RFC 9368/兼容版本协商扩展思路 | `src/packet/quic_transport_params.c` | `tests/test_phase7.c` |
| Retry 完整性标签 | v1/v2 Retry integrity tag 计算与校验 | RFC 9001, RFC 9369 | `src/packet/quic_retry.c` | `tests/test_phase7.c` |
| 包号处理 | 包号长度推导、截断包号恢复、包号编码 | RFC 9000, RFC 9001 | `src/packet/quic_packet_protection.c` | `tests/test_phase8.c` |
| Initial 包保护 | Initial 报文 AEAD 保护 / 解保护、头部保护 | RFC 9001, RFC 9369 | `src/packet/quic_packet_protection.c` | `tests/test_phase8.c` |
| 在途包队列 | 记录 ack-eliciting 数据包、飞行字节、ACK 删除 | RFC 9002（极简子集） | `src/recovery/loss_detector.c` | `tests/test_phase5_1.c` |
| ACK 帧解析 | 解析 ACK/ACK_ECN frame，应用到在途队列 | RFC 9000, RFC 9002（极简子集） | `src/recovery/quic_ack.c` | `tests/test_phase9.c` |
| Initial 头解析 | 解析 Initial 包中的 token length、length、pn offset | RFC 9000 | `src/packet/quic_initial.c` | `tests/test_phase10.c` |
| 连接级 Initial 接收 | 连接对象初始化、设置 Initial 密钥、接收并解析 Initial 包 | RFC 9000, RFC 9001, RFC 9369 | `src/transport/quic_connection.c` | `tests/test_phase10.c` |
| 连接基础骨架 | 显式状态机、三类包号空间、统一收包/发包骨架、统一定时器与事件入口 | RFC 9000, RFC 9002 | `src/transport/quic_connection.c` | `tests/test_phase11.c` |
| TLS 1.3 QUIC 握手核心 | BoringSSL QUIC 回调、CRYPTO 重组、transport parameters 注入/解析、Handshake/1-RTT 密钥安装与旧密钥丢弃 | RFC 9001 | `src/tls/quic_tls.c`, `src/transport/quic_crypto_stream.c` | `tests/test_phase12.c` |
| 最小端到端握手示例 | UDP server/client 建立加密 QUIC 连接、交换 1-RTT PING | RFC 9000, RFC 9001 | `example/server.c`, `example/client.c`, `topo.py` | `tests/test_phase12.c`, `make topo-auto` |

### 部分实现功能

以下能力已有“骨架”或“语法层支持”，但与 RFC 的完整要求相比仍不完整。

- 帧处理目前主要是“可遍历、可跳过、可抽取少量关键字段”，并未对大多数帧建立完整状态机或副作用。
- `quic_conn_recv_initial()` 能处理 ACK、CRYPTO 和若干通用帧，但没有严格按 RFC 9000 对 Initial 包中允许出现的帧类型做完整约束。
- 传输参数虽然支持编解码多个标准字段，但缺少默认值补齐、语义合法性校验和跨字段约束检查。
- Version Negotiation 仅实现报文生成，没有实现完整的客户端侧协商处理、降级防护或兼容版本协商状态机。
- ACK/恢复模块只实现了最小 in-flight bookkeeping；虽然连接层已有统一定时器入口，但尚未实现 RTT 估计、丢包检测、PTO 或拥塞控制。

### 尚未实现功能

与 RFC 9000/9001/9002/9369 相比，当前仓库明显缺失以下核心能力：

- 0-RTT 数据路径
- 更完整的 Handshake/1-RTT 包收发路径（当前仅覆盖握手所需 CRYPTO、HANDSHAKE_DONE、PING）
- 流管理、流状态机、重组、发送调度与流量控制
- 连接级流量控制、最大数据量与 stream limit enforcement
- 连接迁移、路径验证、CID 生命周期管理与 NEW_CONNECTION_ID 语义执行
- Stateless Reset 构造与处理
- Retry 包完整构造与服务端地址验证流程
- 丢包检测、RTT 估计、PTO、NewReno 拥塞控制等 RFC 9002 主体逻辑
- 密钥更新（Key Update）与更完整的密钥生命周期管理
- ECN 路径验证与拥塞反馈处理
- 应用层协议（例如 HTTP/3）集成

## 测试说明

现有测试以“分阶段”方式组织：

- `test1`: 包头预解析与 UDP 批量接收
- `test2`: 版本路由与版本协商生成
- `test3`: Initial 密钥派生
- `test4`: varint 解码与基础帧解析
- `test5_1`: 在途包队列管理
- `test6`: varint 编码回环与全帧类型语法覆盖
- `test7`: 传输参数编解码与 Retry 完整性标签
- `test8`: 包号处理与 RFC 向量下的 Initial 包保护/解保护
- `test9`: ACK frame 解析与应用
- `test10`: Initial 头解析与连接级 Initial 接收
- `test11`: 阶段 0 连接骨架，覆盖状态机、包号空间、统一收包/发包入口与定时器事件入口
- `test12`: 阶段 1 TLS/QUIC 握手核心，覆盖 CRYPTO 重组、transport parameters、Handshake/1-RTT 密钥安装、旧密钥丢弃与内存内端到端握手

运行方式：

```bash
make test1
make test2
make test3
make test4
make test5_1
make test6
make test7
make test8
make test9
make test10
make test11
make test12
```

或直接编译全部当前测试目标：

```bash
make all
```

如果要运行最小端到端示例与证书生成：

```bash
make quic-demo
```

如果本机具备 root 权限并已安装 Mininet，可以直接在拓扑上自动验证：

```bash
make topo-auto
```

## 当前定位

如果你的目标是“完整 QUIC 协议栈”，这个仓库仍处于早期构件验证阶段；如果你的目标是“逐模块验证 QUIC 关键部件并继续演进”，当前结构已经适合作为后续扩展的基础。

基于 README.md 里的缺失项，这个仓库要补成“完整 QUIC 协议栈”，建议按依赖关系分 7 个阶段推进，而不是按 RFC 章节平铺开发。核心顺序应当是：先把连接模型和密钥生命周期搭稳，再补完整收发管线，再做流控/恢复，最后上迁移和应用层。

阶段 0：重构基础骨架。先把当前“只够处理 Initial 接收”的实现整理成统一连接对象，补上连接状态机、包号空间抽象、收包路径/发包路径骨架、统一定时器与事件入口。完成标志是代码里能明确区分 Initial、Handshake、Application Data 三个包号空间，而不是把逻辑散在单个函数里。

阶段 1：已完成 TLS 1.3 与 QUIC 握手核心。当前已实现 CRYPTO 数据重组、和 BoringSSL secrets callback 对接、传输参数在握手中的注入与解析、Handshake 密钥和 1-RTT 密钥安装、旧密钥丢弃，以及最小化的 1-RTT PING 验证路径。客户端和服务端已经可以真实完成 QUIC 握手，而不只是派生 Initial 密钥。

阶段 2：补齐完整包收发管线。实现 Handshake、0-RTT、1-RTT、短头包的真实解析和构造；补齐 ACK 生成、包构造、包号分配、包保护/解保护在各密钥级别上的切换；把 Version Negotiation、Retry、放大攻击限制串进真实收发流程。完成标志是两端可以建立连接并发送 1-RTT 数据包。

阶段 3：实现流与连接级流控。这里要补 stream 状态机、发送缓冲、接收重组、FIN/RESET/STOP_SENDING、MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS 的 enforcement，以及基本调度器。完成标志是能在多个流上稳定双向传输数据，并正确触发流控帧。

阶段 4：实现 RFC 9002 的恢复与拥塞控制主体。要把现在的极简 in-flight bookkeeping 扩展成完整 sent-packet map、RTT 估计、ack delay 处理、loss detection、PTO、拥塞窗口、慢启动/拥塞避免、ECN 验证。完成标志是出现丢包、乱序、重传和超时时，连接仍能收敛并继续传输。

阶段 5：实现连接管理与迁移能力。补齐 CID 生命周期、NEW_CONNECTION_ID/RETIRE_CONNECTION_ID 语义、path validation、connection migration、preferred_address、stateless reset、idle timeout、close/error handling、token 与地址验证。完成标志是连接不仅能“建立和传数据”，还能正确处理迁移、关闭和异常路径。

阶段 6：接应用层与做互操作收尾。最后再接 HTTP/3 或至少一个稳定的应用层 demo，补 qlog/metrics/fuzzing/interop tests，和 quiche、ngtcp2、msquic 这类实现做互通验证。完成标志是仓库不再只是协议构件集合，而是一个可对外使用、可验证、可调试的完整 QUIC 栈。

如果你要更可执行一点，我下一步可以把这 7 个阶段继续展开成“每阶段需要新增哪些 .c/.h 文件、哪些测试目标、哪些 RFC 小节对应到哪些实现任务”的开发计划。
