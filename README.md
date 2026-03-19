# AI-QUIC

`AI-QUIC` 是一个面向学习和分阶段实现的 QUIC 协议实验仓库。当前代码已经完成阶段 0、阶段 1、阶段 2、阶段 3 和阶段 4，并已落地阶段 5 的核心连接管理/迁移路径与阶段 6 子阶段 A 的应用接口层：除 QUIC v1/v2 的报文解析、Initial 密钥派生、Initial 报文保护/解保护、传输参数处理、最小化 ACK 与在途包管理外，还补上了基于 BoringSSL 的 TLS 1.3 QUIC 回调层、CRYPTO 数据重组、transport parameters 注入与解析、Handshake/0-RTT/1-RTT/短头包的真实收发、ACK 生成、Version Negotiation/Retry 运行时处理、服务端放大攻击限制、多流状态管理与基础流控、RFC 9002 恢复/拥塞控制主体，以及面向应用的 `quic_api` 与 qlog/metrics 基础观测。项目仍然不是完整的 QUIC 协议栈，但已经从“协议构件验证平台”推进到“具备阶段化真实验证能力的 QUIC 实验栈”。

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
- `src/transport/`: UDP 批量接收、连接骨架、CRYPTO 缓冲与流状态管理
- `src/app/`: 面向应用层的稳定接口与观测封装
- `API.md`: 面向应用层使用者的对外 API 文档
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
8. 在阶段 2 中补齐最小可运行的包收发管线：Initial、Handshake、0-RTT、1-RTT、短头包的解析与构造，ACK 自动生成，Version Negotiation 与 Retry 串接，服务端放大攻击限制，以及真实 UDP 示例上的 1-RTT 加密收发。
9. 在阶段 3 中补齐 stream 状态机、发送缓冲、接收重组、FIN/RESET/STOP_SENDING、MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS enforcement，以及基本多流调度器；当前 `example/` 已能在两个双向流上完成双向数据交换。
10. 在阶段 4 中补齐 RFC 9002 的恢复与拥塞控制主体：sent-packet metadata、RTT 估计、ACK delay、loss detection、PTO、拥塞窗口、persistent congestion，以及 congestion-limited / flow-control-limited / application-limited 的区分验证。
11. 在阶段 5 中补齐连接管理与迁移核心路径：CID/token 基础状态机、idle timeout、closing/draining、stateless reset、path validation、preferred-address 迁移，以及对应的真实网络验证入口。
12. 在阶段 6 子阶段 A 中补上一层稳定的 `quic_api`，并增加 qlog 风格事件、基础 metrics、app demo 和面向应用的 loopback/topology 自测入口。

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
| 阶段 2 包收发管线 | Handshake、0-RTT、1-RTT、短头包的解析/构造，ACK 生成，Version Negotiation，Retry，服务端放大攻击限制 | RFC 9000, RFC 9001, RFC 9002, RFC 9369 | `src/tls/quic_tls.c`, `src/packet/quic_version.c`, `src/packet/quic_retry.c` | `tests/test_phase13.c` |
| 阶段 3 流与流控基础 | stream 状态机、发送缓冲、接收重组、FIN/RESET/STOP_SENDING、MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS enforcement、基本调度器 | RFC 9000 | `src/transport/quic_stream.c`, `src/tls/quic_tls.c` | `tests/test_phase14.c` |
| 阶段 4 恢复与拥塞控制主体 | sent-packet metadata、RTT 估计、ACK delay、packet-threshold / time-threshold loss detection、PTO、拥塞窗口、persistent congestion、application-limited / flow-control-limited 区分 | RFC 9002 | `include/quic_recovery.h`, `src/recovery/loss_detector.c`, `src/tls/quic_tls.c` | `tests/test_phase15.c`, `tests/test_phase16.c`, `tests/test_phase17.c`, `make topo-stage4-clean`, `make topo-stage4-lossy` |
| 阶段 5 连接管理与迁移核心路径 | `NEW_CONNECTION_ID` / `RETIRE_CONNECTION_ID` 基础语义、token、idle timeout、closing/draining、stateless reset、`PATH_CHALLENGE` / `PATH_RESPONSE`、`preferred_address` 迁移基础路径 | RFC 9000 | `src/tls/quic_tls.c`, `example/client.c`, `example/server.c`, `topo.py` | `tests/test_phase18.c`, `tests/test_phase19.c`, `tests/test_phase20.c`, `make topo-stage5-preferred` |
| 最小端到端多流示例 | UDP server/client 建立加密 QUIC 连接、在两个 bidirectional stream 上双向收发应用数据，并交换 1-RTT PING | RFC 9000, RFC 9001 | `example/server.c`, `example/client.c`, `topo.py` | `tests/test_phase12.c`, `tests/test_phase13.c`, `tests/test_phase14.c`, `make quic-demo` |
| 阶段 6 子阶段 A 应用接口与观测 | 稳定 `quic_api`、根目录 `API.md`、qlog 风格事件、基础 metrics、连接/路径/流快照、双 stream app demo、独立 fuzz smoke 入口 | RFC 9000, RFC 9001, RFC 9002 | `include/quic_api.h`, `src/app/quic_api.c`, `API.md`, `example/app_client.c`, `example/app_server.c`, `tests/fuzz/quic_fuzz_smoke.c`, `topo.py` | `tests/test_phase21.c`, `tests/test_phase22.c`, `tests/test_phase23.c`, `make fuzz-smoke`, `make quic-app-demo` |

### 部分实现功能

以下能力已有“骨架”或“语法层支持”，但与 RFC 的完整要求相比仍不完整。

- 帧处理目前主要是“可遍历、可跳过、可抽取少量关键字段”，并未对大多数帧建立完整状态机或副作用。
- `quic_conn_recv_initial()` 与 `quic_tls_conn_handle_datagram()` 已能处理 ACK、CRYPTO、PING、HANDSHAKE_DONE、NEW_TOKEN、STREAM、RESET_STREAM、STOP_SENDING、MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS 等关键帧，但没有对各包级别的合法帧集合做完整约束，也没有接入 blocked/path/CID 管理等剩余控制帧状态机。
- 传输参数虽然支持编解码多个标准字段，但缺少默认值补齐、语义合法性校验和跨字段约束检查。
- Version Negotiation 与 Retry 已串进真实收发流程，但仍缺少降级防护、兼容版本协商和更完整的 token/地址验证策略。
- 0-RTT 已具备包级解析/构造路径，但仍未接入真实应用数据、重放风险约束和会话票据语义。
- 恢复/拥塞控制主体已经落地，但 ECN 发送标记、ACK_ECN 驱动的完整路径验证和更细的 benchmark/公平性对比仍未完成。
- 阶段 5 已实现单连接范围内的 CID、path validation、`preferred_address` 和关闭路径基础语义，但尚未完成跨实现互通下的系统性验证。
- 阶段 6 当前已完成“稳定 API + 基础观测 + app demo + fuzz smoke”这一层；外部 interop、libFuzzer/sanitizer 级 fuzzing 和 HTTP/3/QPACK 仍未接入。

### 尚未实现功能

与 RFC 9000/9001/9002/9369 以及阶段 6 的目标相比，当前仓库仍明显缺失以下核心能力：

- 外部实现 interop 自动化（当前只完成对象筛选与本仓库内部准备，尚未接入 `xquic` / `quic-interop-runner`）
- 更系统的 benchmark 体系（当前 `topo.py` 仍以本仓库 profile 为主，尚未接入 `quic-network-simulator`）
- HTTP/3 / QPACK 集成与对应测试
- 密钥更新（Key Update）与更完整的密钥生命周期管理
- 完整 0-RTT / resumption / ticket 语义
- ECN 路径验证与拥塞反馈处理

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
- `test13`: 阶段 2 完整包收发管线，覆盖 ACK 生成、交错时序下的后续 Initial、Retry、Version Negotiation、放大攻击限制、0-RTT 与短头包路径
- `test14`: 阶段 3 流与流控基础，覆盖多流双向数据传输、MAX_DATA/MAX_STREAM_DATA 增长，以及 STOP_SENDING 触发 RESET_STREAM
- `test15`: 阶段 4 恢复状态机，覆盖 RTT 采样、ACK delay、loss detection、PTO 与包号空间清理
- `test16`: 阶段 4 拥塞控制与流控/应用受限交互，覆盖 slow start、窗口收缩与受限状态区分
- `test17`: 阶段 4 bulk 传输与阻塞回归，覆盖内存内长流、大文件与 `BUILD_BLOCKED`/恢复行为
- `test18`: 阶段 5 CID / token / termination 状态机，覆盖 `NEW_CONNECTION_ID`、idle timeout、closing/draining 与 stateless reset
- `test19`: 阶段 5 path validation / migration 状态机，覆盖 `PATH_CHALLENGE` / `PATH_RESPONSE`、rebind 和 `preferred_address`
- `test20`: 阶段 5 真实网络迁移入口，覆盖 `preferred_address` 迁移后的文件传输与关闭路径
- `test21`: 阶段 6 应用 API 与关闭语义，覆盖稳定应用接口、双 stream 请求/响应和优雅关闭
- `test22`: 阶段 6 qlog/metrics 与准 fuzz 回归，覆盖事件导出、基础指标采样和包头解析压力回归
- `test23`: 阶段 6 app demo 本机 loopback，覆盖 `quic_app_server/quic_app_client`、qlog 文件落盘和真实 UDP 请求/响应
- `fuzz-smoke`: 阶段 6 独立 fuzz smoke harness，覆盖包头解析、frame 解析、transport parameters、ACK range 与 stream 状态机

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
make test13
make test14
make test15
make test16
make test17
make test18
make test19
make test20
make test21
make test22
make test23
make fuzz-smoke
```

或直接编译全部当前测试目标：

```bash
make all
```

如果要运行最小端到端示例与证书生成：

```bash
make quic-demo
```

本机回环验证可以直接运行：

```bash
./tests/bin/quic_server 127.0.0.1 4434 tests/certs/server_cert.pem tests/certs/server_key.pem
./tests/bin/quic_client 127.0.0.1 4434
```

如果本机具备 root 权限并已安装 Mininet，可以直接在拓扑上自动验证：

```bash
make topo-auto
```

`topo-auto` 与 `topo-auto-file` 默认都会重复执行 5 轮；只有全部轮次都通过，目标才算成功。

如果要在拓扑中验证真实文件上传/下载，可以运行：

```bash
make topo-auto-file
```

如果要按阶段 4 的大 bulk profile 验证恢复与拥塞控制，可以运行：

```bash
make topo-stage4-clean
make topo-stage4-lossy
```

如果要按阶段 5 / 阶段 6 的当前入口继续验证，可以运行：

```bash
make topo-stage5-preferred
make topo-stage6-clean
make topo-stage6-lossy
```

也可以直接覆盖链路参数：

```bash
sudo python3 topo.py --auto-file --profile clean-bdp --rounds 5
sudo python3 topo.py --auto-file --profile lossy-recovery --bw 100 --delay 20 --loss 2 --rounds 5
```

该模式会在 `tests/data/topo-transfer/` 下生成和校验以下文件：

- `client_upload.bin`: 客户端上传源文件
- `server_received.bin`: 服务端接收后的文件
- `server_source.bin`: 服务端下发源文件
- `client_downloaded.bin`: 客户端下载后的文件

当前测试维护原则：

- 现有分阶段测试、本机回环和 `topo.py`/`Makefile` 入口都必须保留，不能为了接新阶段而替换掉已经稳定的旧验证链路。
- 新测试应优先增量接入现有三层链路：单元/阶段测试 -> 本机 loopback -> 真实拓扑。
- 如果新的网络验证会明显扰动当前稳定的 `topo.py` profile，优先新开独立的 `topo_*.py` 或阶段专用拓扑脚本，而不是破坏已有 stage4/stage5/stage6 入口。

## 当前定位

如果你的目标是“完整 QUIC 协议栈”，这个仓库目前处于“核心 transport/recovery 已成形、连接管理与应用接口已落地、外部互通与 HTTP/3 尚待补齐”的中后段阶段；如果你的目标是“逐模块验证 QUIC 关键部件并继续演进”，当前结构已经具备持续扩展与分层验证的基础。

基于 README.md 里的缺失项，这个仓库要补成“完整 QUIC 协议栈”，建议按依赖关系分 7 个阶段推进，而不是按 RFC 章节平铺开发。核心顺序应当是：先把连接模型和密钥生命周期搭稳，再补完整收发管线，再做流控/恢复，最后上迁移和应用层。

阶段 0：重构基础骨架。先把当前“只够处理 Initial 接收”的实现整理成统一连接对象，补上连接状态机、包号空间抽象、收包路径/发包路径骨架、统一定时器与事件入口。完成标志是代码里能明确区分 Initial、Handshake、Application Data 三个包号空间，而不是把逻辑散在单个函数里。

阶段 1：已完成 TLS 1.3 与 QUIC 握手核心。当前已实现 CRYPTO 数据重组、和 BoringSSL secrets callback 对接、传输参数在握手中的注入与解析、Handshake 密钥和 1-RTT 密钥安装、旧密钥丢弃，以及最小化的 1-RTT PING 验证路径。客户端和服务端已经可以真实完成 QUIC 握手，而不只是派生 Initial 密钥。

阶段 2：已完成完整包收发管线。当前已实现 Handshake、0-RTT、1-RTT、短头包的真实解析和构造；补齐 ACK 生成、包构造、包号分配、包保护/解保护在各密钥级别上的切换；并把 Version Negotiation、Retry、放大攻击限制串进真实收发流程。内存内回归和本机 UDP `example/` 均已证明两端可以建立连接并发送 1-RTT 数据包。

阶段 3：已完成流与连接级流控基础。当前已实现 stream 状态机、发送缓冲、接收重组、FIN/RESET/STOP_SENDING、MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS 的 enforcement，以及基本调度器。`tests/test_phase14.c` 和本机 UDP `example/` 已证明双方能在多个双向流上稳定传输数据，并能触发和消费流控更新帧。

阶段 4：已完成 RFC 9002 的恢复与拥塞控制主体。当前已经补齐 sent-packet metadata、RTT 估计、ack delay 处理、packet-threshold / time-threshold loss detection、PTO、拥塞窗口、慢启动 / congestion avoidance、persistent congestion，以及区分 congestion-limited / flow-control-limited / application-limited 的测试。`tests/test_phase15.c`、`tests/test_phase16.c`、`tests/test_phase17.c` 已覆盖恢复状态机、拥塞控制与内存内 bulk 传输；`topo.py` 也已支持 `clean-bdp`、`lossy-recovery`、`app-limited` 等 profile 驱动的真实网络大文件验证。

#### 阶段 4 设计细化

阶段 4 不应再把“恢复”“拥塞控制”“流控”“真实网络验证”混在一个大补丁里完成，而应分为 4 个层次推进：恢复状态机、拥塞控制器、流控/应用受限交互、真实网络验证。当前阶段 3 已经有流状态机和基础流控，因此阶段 4 的重点不是重新实现流控，而是确保拥塞控制不会把“拥塞受限”和“流控受限”混淆。

##### 1. 设计边界

- 本阶段先做单路径 RFC 9002 主体，不同时引入连接迁移、多路径或 Key Update。
- 本阶段的发送约束分成 3 类并显式区分：
  - `congestion_window` 约束：由拥塞控制决定能发多少字节。
  - `bytes_in_flight` 约束：由已发未确认的 ack-eliciting 包决定。
  - flow control 约束：由 `MAX_DATA` / `MAX_STREAM_DATA` / `MAX_STREAMS` 决定应用还能排入多少数据。
- “流控是否正确”在阶段 3 已有基础，本阶段需要补的是：
  - 当连接是 flow-control-limited 或 application-limited 时，拥塞窗口不应被错误增长。
  - 当 flow control 被放开后，发送器应能重新利用已有拥塞窗口继续发包。

##### 2. 建议的数据结构与模块划分

- 扩展 `include/quic_recovery.h` 与 `src/recovery/loss_detector.c`，不再只保存“包号 + 大小 + ack-eliciting”，而是至少补齐：
  - `time_sent`
  - `sent_bytes`
  - `ack_eliciting`
  - `in_flight`
  - `is_crypto_packet`
  - `is_pto_probe`
  - `packet_number_space`
  - 指向待重传数据的引用或重建信息
- 在连接对象或 TLS 连接对象中新增统一恢复状态：
  - RTT 状态：`latest_rtt`、`smoothed_rtt`、`rttvar`、`min_rtt`、`first_rtt_sample`
  - loss detection 状态：`loss_time[space]`、`largest_acked[space]`、`pto_count`、`time_of_last_ack_eliciting_packet[space]`
  - congestion control 状态：`congestion_window`、`ssthresh`、`bytes_in_flight`、`congestion_recovery_start_time`
  - ECN 状态：每个包号空间的已发送 ECT 统计、对端上报的 `ECT(0)` / `ECT(1)` / `CE` 基线、path 上的 ECN 验证状态
- 建议把实现分成 3 个恢复模块，而不是继续把所有逻辑堆在 `quic_tls.c`：
  - `src/recovery/loss_detector.c`：RTT、ACK 驱动的丢包检测、PTO
  - `src/recovery/congestion_control.c`：NewReno、持久拥塞、是否可发送
  - `src/recovery/ecn.c`：ECN 发送标记策略与 ACK 中 ECN 计数校验

##### 3. 推荐的实现顺序

1. 先把 sent-packet map 做完整，并把当前 `quic_on_packet_sent()` / `quic_on_packet_acked()` 升级为“按包号空间保存与删除 sent packet 元数据”。
2. 实现 RTT 采样、`ack_delay` 处理和 `SetLossDetectionTimer()`，但先不引入拥塞窗口收缩。
3. 实现 ACK 驱动的丢包检测：
   - `kPacketThreshold=3`
   - `kTimeThreshold=9/8`
   - `kGranularity=1ms`
4. 实现 PTO：
   - Initial / Handshake 空间 `max_ack_delay=0`
   - Application 空间只在握手确认后纳入 `max_ack_delay`
   - anti-amplification 受限时不设 PTO
5. 实现 NewReno：
   - 初始窗口
   - slow start
   - congestion avoidance
   - recovery period
   - persistent congestion
6. 最后再加 ECN：
   - 先支持 ACK 中 ECN count 编解码与状态记录
   - 再做路径验证与失败后禁用 ECN

##### 4. 测试设计

阶段 4 不能只靠 `topo.py` 跑通一次。合理测试应拆成 3 层。

第一层：纯恢复/拥塞控制单元测试，建议新增 `tests/test_phase15.c`

- 使用伪时钟而不是 `gettimeofday()`，让 RTT、PTO、loss deadline、persistent congestion 可重复。
- 直接构造 sent packet、ACK frame、丢包序列，验证：
  - RTT 首次采样与平滑更新
  - Application 空间 `ack_delay` 只在握手确认后生效
  - packet-threshold 与 time-threshold 两种丢包判定
  - PTO 选择哪个包号空间、连续 PTO 的指数退避
  - 丢弃 Initial / Handshake keys 后恢复状态是否正确清理

第二层：拥塞控制与流控交互测试，建议新增 `tests/test_phase16.c`

- 不直接依赖 Mininet，而是在内存内驱动 sender / receiver，明确区分 3 种受限状态：
  - congestion-limited
  - flow-control-limited
  - application-limited
- 核心用例应覆盖：
  - slow start 下 ACK 驱动窗口增长
  - loss 或 ECN-CE 触发恢复期与窗口减半
  - persistent congestion 触发窗口坍缩到 minimum window
  - flow control 未放开时窗口不增长
  - flow control 放开后发送立即恢复，且仍受拥塞窗口约束
  - 应用暂时没数据时不把空闲误判为网络拥塞

第三层：真实网络验证，建议新增 `tests/test_phase17.c` 对应的 `example/` / `topo.py` 方案

- 这里不再验证“握手能否成功”，而是验证：
  - 长流在无损/有损链路上是否能逐步打开窗口
  - loss/PTO 后是否还能继续传输
  - receive window 很小时，发送器是否表现为 flow-control-limited 而不是拥塞退避
  - ECN 开启时，ACK 中的 ECN 计数是否可见且能驱动拥塞事件

##### 5. 是否需要改动网络拓扑

阶段 4 早期不需要把当前两主机一交换机拓扑改成更复杂的多交换机网络。现有单 bottleneck 拓扑已经足够验证 RFC 9002 主体。真正需要改的是“链路参数和流量特征的可配置性”，而不是拓扑形状本身。

- 保留当前 `h1 <-> s1 <-> h2` 结构作为默认拓扑。
- `topo.py` 已扩展为 profile 驱动，当前支持 `default`、`clean-bdp`、`lossy-recovery`、`app-limited`，并支持 `--bw`、`--delay`、`--loss` 覆盖默认参数。
- 至少增加以下链路维度：
  - `bw`
  - `delay`
  - `loss`
  - `max_queue_size`
  - `reorder`
  - `ecn`
- 必要时增加一个可选的第三主机做 cross traffic，但这应当是“后续增强项”，不是阶段 4 完成的前置条件。

##### 6. 推荐的网络 profile

为了合理区分拥塞控制与流控，建议至少准备 4 组 profile：

- `clean-bdp`: 无丢包、中等 RTT、较大队列。
  用于观察 slow start 和 congestion avoidance 的基本收敛。
- `lossy-recovery`: 1%-3% 随机丢包、中等 RTT、小到中等队列。
  用于验证 ACK 驱动 loss detection、PTO、恢复期和持久拥塞。
- `flow-limited`: 无丢包，但把 `initial_max_data` / `initial_max_stream_data_*` 设得远小于 BDP。
  用于验证发送端能识别自己是 flow-control-limited，而不是错误触发拥塞退避。
- `ecn-marking`: 无显式丢包、开启 ECN 标记或模拟 ACK 中 ECN 计数。
  用于验证 ECN 状态机和“验证失败后禁用 ECN”。

##### 7. 推荐的流量特征

阶段 4 的真实验证流量不应只是一条几 KB 的小消息。至少需要：

- 单长流 bulk transfer：
  例如单个 stream 连续发送数百 KB 到数 MB，用于打开拥塞窗口。
- 多流并发 bulk transfer：
  验证共享拥塞窗口下的发送调度，不把单流结果误判成连接级结果。
- 应用限速流量：
  周期性停顿再继续，验证 application-limited 时窗口不被错误扩张。
- 小窗口流控流量：
  故意让接收端晚一点发送 `MAX_DATA` / `MAX_STREAM_DATA`，验证 sender 在 flow-control-limited 时的行为。
- PTO 探针场景：
  人工丢弃若干关键 ACK 或数据包，验证 sender 会发送 probe，而不是无限等待。

##### 8. 文档与脚本同步要求

- 当前阶段 4 已满足“`test_phase15/16/17` + `topo.py` profile 驱动验证已落地”的完成条件。
- `topo.py` 当前已经支持 `--profile`、`--bw`、`--delay`、`--loss`；`--queue`、`--ecn` 仍是后续增强项。
- `example/client.c` / `example/server.c` 当前的文件传输模式已可用于 stage4 bulk 验证；更复杂的持续流量模式仍可作为后续增强项。

阶段 5：核心连接管理与迁移路径已落地，当前保留 `tests/test_phase18.c`、`tests/test_phase19.c`、`tests/test_phase20.c` 与 `make topo-stage5-preferred` 作为回归入口。已实现 CID/token 基础状态机、path validation、`preferred_address` 迁移、idle timeout、closing/draining 与 stateless reset 基础路径；更广泛的跨实现互通和 benchmark 收尾留给阶段 6。

#### 阶段 5 设计细化

阶段 5 的目标不是继续堆叠“能收发一些控制帧”，而是把阶段 4 已经稳定下来的收发与恢复主体，扩展成真正具备连接生命周期管理能力的 QUIC 连接。设计时应优先对照 RFC 9000 的以下章节：Section 5.1（Connection ID）、Section 8（Address Validation）、Section 9（Connection Migration）、Section 10（Connection Termination）、Section 18.2（Transport Parameters）、Section 19.15-19.18（NEW_CONNECTION_ID / RETIRE_CONNECTION_ID / PATH_CHALLENGE / PATH_RESPONSE）。

##### 1. 设计边界

- 本阶段先做 RFC 9000 的单路径迁移与连接管理主体，不同时引入 multipath、Key Update 或更复杂的地址共享策略。
- 必须显式区分 5 类行为，不能混成一个“地址变了就切换”的粗糙状态机：
  - 初始建连期的地址验证与 token 校验
  - NAT rebinding / 被动地址变化
  - 主动 connection migration
  - `preferred_address` 驱动的服务端地址切换
  - 连接终止路径：`idle timeout`、`CONNECTION_CLOSE`、`stateless reset`
- 必须把“仍有连接状态”和“已丢失连接状态”区分开来：
  - 有状态终止走 `CONNECTION_CLOSE` + `closing/draining`
  - 无状态终止才允许走 `stateless reset`
- 不能把阶段 4 的单个连接级 anti-amplification 逻辑直接复用为阶段 5 的路径逻辑；迁移后至少要能按 path 追踪“收到多少字节、在验证前允许发多少字节、是否已验证”。

##### 2. 建议的数据结构与模块划分

- 在连接对象下新增本地 CID 表与对端 CID 表，至少记录：
  - `sequence`
  - `cid`
  - `stateless_reset_token`
  - `retire_prior_to`
  - `acked`
  - `retire_pending`
  - `retired`
  - `in_use_path`
- 新增 path 表，而不是只在连接对象里保存一个远端地址。每个 path 至少记录：
  - `local_addr`
  - `peer_addr`
  - `state`：`unknown` / `validating` / `validated` / `failed`
  - `bytes_received`
  - `bytes_sent_before_validation`
  - `challenge_data`
  - `challenge_in_flight`
  - `validation_deadline`
  - `mtu_validated`
  - 与阶段 4 恢复模块对接所需的 path 级 RTT 初值或引用
- 新增 token 管理状态，区分：
  - `Retry token`
  - `NEW_TOKEN` 发放的 address validation token
  - token 所属 QUIC version
  - token 过期时间 / 一次性使用状态
- 连接关闭路径应从普通发送路径中抽离，独立维护：
  - `effective_idle_timeout`
  - `idle_deadline`
  - `closing_deadline`
  - `draining_deadline`
  - 当前 close reason / application error
- 从代码组织上，建议至少拆成以下模块，而不是继续把所有 path/CID/close 逻辑塞进 `quic_tls.c`：
  - `src/transport/quic_cid.c`
  - `src/transport/quic_path.c`
  - `src/transport/quic_token.c`
  - `src/transport/quic_termination.c`

##### 3. 推荐的实现顺序

1. 先补 transport parameters 的语义执行，而不只是解析：
   - `active_connection_id_limit`
   - `disable_active_migration`
   - `preferred_address`
   - `stateless_reset_token`
   - `max_idle_timeout`
2. 实现 `NEW_CONNECTION_ID` / `RETIRE_CONNECTION_ID` 的本地状态机：
   - sequence 单调递增
   - `Retire Prior To` 处理
   - 重复帧幂等
   - 超过 `active_connection_id_limit` 时的错误路径
3. 实现 token 生命周期：
   - Retry token
   - `NEW_TOKEN` token
   - token 与 QUIC version 绑定
   - token 过期与一次性消费
4. 实现 path validation：
   - `PATH_CHALLENGE`
   - `PATH_RESPONSE`
   - challenge data 跟踪
   - validation timeout
   - 1200-byte 扩展要求
5. 在 path validation 之上接 NAT rebinding 与主动迁移：
   - 握手确认前禁止主动迁移
   - 新 path 上使用新的 peer CID
   - 验证成功前限制发送
6. 再实现 `preferred_address`：
   - 客户端收到服务端 `preferred_address` 后切换地址
   - 切换必须走 path validation，而不是直接认定成功
7. 最后实现连接终止完整路径：
   - `idle timeout`
   - liveness `PING`
   - `closing/draining`
   - `stateless reset` 的生成与检测

##### 4. 测试设计

阶段 5 不应只靠一次 `topo.py` 跑通。建议像阶段 4 一样拆成 3 层。

第一层：CID / token / termination 纯状态机测试，建议新增 `tests/test_phase18.c`

- 直接在内存内验证：
  - `NEW_CONNECTION_ID` 重复接收是否幂等
  - `Retire Prior To` 是否正确驱动本地 retirement
  - `active_connection_id_limit` 超限是否触发 `CONNECTION_ID_LIMIT_ERROR`
  - `RETIRE_CONNECTION_ID` 是否只允许 retire 已发放的 sequence
  - `max_idle_timeout` 的 effective value 是否取双方最小值
  - idle timer 是否只在“成功处理入站包”或“首次 ack-eliciting 发送”后重置
  - `closing` / `draining` 是否遵守“三倍 PTO”量级的保留时间
  - stateless reset token 是否只对 active / used CID 生效

第二层：path validation 与迁移状态机测试，建议新增 `tests/test_phase19.c`

- 不依赖 Mininet，直接驱动两端连接对象，验证：
  - `PATH_CHALLENGE` 必须带不可预测的 8 字节数据
  - `PATH_RESPONSE` 只能回显已收到的 challenge，且每个 challenge 只回一次
  - 新 path 在验证成功前不能被视为 fully validated
  - 验证失败定时器应接近 RFC 9000 推荐的 `3 * max(current PTO, new-path PTO)`
  - `disable_active_migration` 打开时，主动迁移应被拒绝或只做丢弃/验证而不直接切换
  - `preferred_address` 切换必须走完整 path validation
  - NAT rebinding 不应被误判成协议错误或直接关连接

第三层：真实网络验证，建议新增 `tests/test_phase20.c` 与 `topo.py` 的 stage5 profile

- 这里验证的重点不再是“能否传一个文件”，而是：
  - bulk 传输进行中触发客户端地址变化，连接是否保持
  - bulk 传输进行中切到 `preferred_address`，是否仍能完成
  - 空闲一段时间后，`idle timeout` 是否按协商值关闭
  - 关闭后继续收到旧包时，是否进入正确的 `closing/draining/stateless reset` 路径
  - 服务器丢状态或重启后，客户端是否能把 trailing token 正确识别为 stateless reset

##### 5. 是否需要改动网络拓扑

与阶段 4 不同，阶段 5 仅靠现有“两个主机、一条稳定 path”的默认运行模式不够。要合理测试 migration，拓扑或地址配置至少要支持“同一连接切换到另一条地址路径”。

- 最小改法不是引入复杂多交换机，而是给 `h1` 和 `h2` 各准备两组地址或两块接口，使同一主机能在测试中切到另一条 path。
- 如果 Mininet 脚本实现更方便，也可以保留单交换机结构，但为主机增加第二接口：
  - 初始路径：`h1-eth0 <-> s1 <-> h2-eth0`
  - 迁移路径：`h1-eth1 <-> s1 <-> h2-eth1`
- `preferred_address` 测试更适合服务端具备第二地址，而不是只换端口。
- `stateless reset` 测试不一定需要新增主机，但需要脚本能够模拟“服务端失去连接状态后仍收到旧连接包”。
- 阶段 5 不必一开始就引入 cross traffic 主机；真实重点是地址变化与 path validation，不是公平性。

##### 6. 推荐的 stage5 profile 与流量特征

为了把连接管理问题和普通丢包/拥塞问题区分开，建议至少准备以下 profile：

- `nat-rebind`：
  - 传输中只改变客户端源地址/端口，验证被动地址变化与 CID 切换。
- `active-migration`：
  - 传输中主动切到另一接口或另一 IP，验证 path validation 与新 CID 使用。
- `preferred-address`：
  - 握手后由客户端切向服务端 `preferred_address`，验证服务端给出的 CID 与 reset token 语义。
- `idle-timeout`：
  - 先完成少量数据交换，再静默超过协商超时，验证双方是否按 effective timeout 清理连接。
- `stateless-reset`：
  - 服务器在建立连接后丢失状态，客户端继续发包，验证 reset 检测与进入 draining。

阶段 5 的真实流量特征也应调整：

- 迁移必须发生在连接已建立且有持续数据流时，不能只在空连接上做一次 `PATH_CHALLENGE`。
- 至少保留一个长 stream 或文件传输作为迁移载荷，避免“迁移成功但应用面其实已经结束”。
- `idle-timeout` 场景需要显式静默窗口，而不是靠脚本 sleep 后立即退出。
- `stateless-reset` 场景需要在 reset 后继续观察客户端是否停止发包，而不是只看一条日志。

##### 7. 文档与脚本同步要求

- `topo.py` 需要为阶段 5 预留新的控制参数，例如：
  - `--migrate-after-ms`
  - `--migrate-after-bytes`
  - `--preferred-address`
  - `--idle-wait-ms`
  - `--drop-server-state`
- `example/client.c` / `example/server.c` 需要暴露 path/CID 事件日志，否则拓扑测试很难区分“连接还活着”与“其实只是重新建了一个连接”。
- 阶段 5 完成前，README 中“已完成能力”不应提前宣称迁移或 stateless reset 已实现；只有 `test_phase18/19/20` 与对应 `topo.py` profile 稳定通过后，才能把这一阶段标记为完成。

阶段 6：接应用层与做互操作收尾。最后再接 HTTP/3 或至少一个稳定的应用层 demo，补 qlog/metrics/fuzzing/interop tests，和 quiche、ngtcp2、msquic 这类实现做互通验证。完成标志是仓库不再只是协议构件集合，而是一个可对外使用、可验证、可调试的完整 QUIC 栈。

当前状态：阶段 6 进行中，子阶段 A 已完成。

- 已落地：
  - `include/quic_api.h` / `src/app/quic_api.c`：稳定应用接口，封装连接创建、收发、stream 读写、timeout 驱动、迁移入口和 close 入口
  - 根目录 `API.md`：对外 API 用法、数据结构、事件/metrics 和示例说明
  - qlog 风格事件队列与 JSON 导出
  - 基础 metrics 导出：收发字节、拥塞窗口、在途字节、PTO 计数、活跃 stream/path 数，以及 JSON 导出
  - 连接/路径/流快照接口，避免应用层直接依赖内部 `quic_tls` 结构
  - `example/app_client.c` / `example/app_server.c`：基于 `quic_api` 的最小双 stream 请求/响应 demo
  - `tests/test_phase21.c` / `tests/test_phase22.c` / `tests/test_phase23.c`
  - `tests/fuzz/quic_fuzz_smoke.c` 与 `make fuzz-smoke`
  - `topo.py` 的 `app-demo-clean` / `app-demo-lossy` profile，以及 `make topo-stage6-clean` / `make topo-stage6-lossy`
- 已验证：
  - `make test21 test22`
  - `make fuzz-smoke`
  - `make test23`
  - `make TEST_REPEAT=1 test18 test19 test20`
  - `python3 -m py_compile topo.py`
- 尚未完成：
  - 外部实现 interop（当前优先对象已收敛为 `xquic`，但尚未真正接入）
  - HTTP/3 / QPACK
  - 更系统的 fuzz harness（当前已有 smoke harness，但还不是 libFuzzer / sanitizer 级别）

##### 阶段 6 下半部分：调研结论与对象选择

这一轮先不写实现代码，先确定 interop 对象和 benchmark 基线。当前推荐结论如下：

- interop 首选对象：`xquic`
- benchmark 首选框架：`quic-network-simulator`
- correctness 框架：`quic-interop-runner`
- `h2load` 暂不作为当前主 benchmark，只在后续 HTTP/3 子阶段再引入

选择 `xquic` 的原因：

- `xquic` 官方仓库明确声明自己是 QUIC 与 HTTP/3 的 client/server 实现，并且“regularly tested with other QUIC implementations”。
- `xquic` 官方文档已经给出 `test_client` / `test_server` 的直接运行方式，适合作为本仓库下半阶段的第一个外部互通对象。
- `xquic` 仓库本身包含 `interop/` 目录，且其官方文档列出 `qlog`、拥塞控制、迁移等特性，说明它不仅能作为“能握手的对象”，也适合作为后续迁移与可观测性比对对象。
- 从工程形态看，`xquic` 与本仓库同为 C 语言、同样使用 BoringSSL 路线，接入成本和日志对比成本都低于 Go/Rust/C# 实现。

当前建议的 interop 分阶段顺序：

1. 先做本机 loopback 的双实现 smoke test：
   - 我方 client -> xquic server
   - xquic client -> 我方 server
2. 再接 `quic-interop-runner`，优先只启用与当前实现边界匹配的 case：
   - `handshake`
   - `transfer`
   - `retry`
   - `rebind-port`
   - `rebind-addr`
   - `connectionmigration`
3. 等这些 case 稳定后，再扩大到：
   - `multiconnect`
   - `transferloss`
   - `handshakeloss`
4. 当前暂缓的 case：
   - `http3`
   - `zerortt`
   - `resumption`
   - `keyupdate`
   - `v2`
   - `chacha20`

这些暂缓项不是说不做，而是它们依赖本仓库当前尚未完成的 HTTP/3、完整 0-RTT/恢复票据、Key Update 或更细的版本/密码套件覆盖，不适合作为下半阶段第一批 interop 目标。

benchmark 选择结论：

- 当前阶段不建议把 `h2load` 作为主 benchmark。
  原因是 `h2load` 的强项是 HTTP/3 / HTTP/2 / HTTP/1.1 压测；而本仓库当前尚未实现 HTTP/3，因此现在引入它会把“应用层协议未完成”和“QUIC transport 性能”混在一起。
- 当前阶段更合适的 benchmark 是 `quic-network-simulator`。
  它是 QUIC 社区官方维护的 ns-3 网络模拟框架，目标就是“benchmarking and measuring the performance of QUIC implementations under various network conditions”，并且天然适合和 `quic-interop-runner` 的 Docker endpoint 形态复用。
- `quic-interop-runner` 本身则承担 correctness 与 feature coverage，不应替代 benchmark；但它的公开运行结果已经把 `goodput`、`crosstraffic`、`blackhole` 等 measurement case 暴露出来，因此下半阶段完全可以采用“interop-runner 跑协议正确性，network-simulator 跑性能场景”的二层结构。

benchmark 基线建议如下：

- 基准对象：
  - 我方实现 vs `xquic`
- 指标：
  - handshake completion time
  - transfer completion time
  - goodput
  - bytes in flight / cwnd 演化
  - PTO 次数
  - 丢包恢复后的完成时延
  - qlog / pcap 可用性
- 第一批场景：
  - `simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25`
  - `simple-p2p --delay=60ms --bandwidth=20Mbps --queue=50`
  - `simple-p2p --delay=20ms --bandwidth=10Mbps --queue=25` 并叠加轻度丢包
  - `single-tcp` cross traffic 场景，用于观察 goodput 与恢复行为

候选 benchmark / 测试框架筛选：

- `quic-network-simulator`：选作当前主 benchmark。
  - 适配原因：官方定位就是 QUIC benchmark，能系统控制时延、带宽、队列、交叉流量，比当前 `topo.py` 更接近阶段 6 下半部分需要的长期基线。
  - 适用范围：transport 层性能、拥塞控制、恢复行为、跨实现 goodput 对比。
- `quic-interop-runner`：选作 correctness / feature coverage 框架，不单独承担 benchmark 角色。
  - 适配原因：官方已经定义 `handshake`、`transfer`、`retry`、`rebind-port`、`rebind-addr`、`connectionmigration` 等 test case，并且能保存日志、pcap、`SSLKEYLOGFILE` 与 `QLOGDIR`。
  - 适用范围：外部互通、回归矩阵、功能边界验证。
- `h2load`：暂缓。
  - 不选当前主 benchmark 的原因：它本质上是 HTTP/3 / HTTP/2 / HTTP/1.1 压测工具；本仓库当前还没有 HTTP/3，因此现在用它会把 transport 问题和应用层协议实现缺口混在一起。
  - 后续位置：等 HTTP/3 子阶段落地后，再把它接入 stage 6 的后半部分。

interop 对象筛选：

- 第一优先级：`xquic`
  - 选择理由：同为 C 语言、BoringSSL 路线、官方文档直接提供 `test_client` / `test_server`、并且官方明确说明会定期做 interoperability testing，接入成本最低。
- 第二梯队候选：`ngtcp2`、`quiche`、`msquic`
  - 保留原因：它们适合补充跨语言 / 跨工程风格的覆盖面。
  - 暂不作为第一目标：和当前仓库在构建系统、依赖模型、日志习惯上的差异更大，早期接入会放大环境问题而不是优先验证 transport/迁移实现。

筛选结论总结：

- 现在就应该引入：`xquic`、`quic-interop-runner`、`quic-network-simulator`
- 暂缓到 HTTP/3 子阶段：`h2load`
- 不选作当前主 benchmark：只面向特定实现的 QUIC 压测工具

#### 阶段 6 设计细化

阶段 6 的目标不是再补一个“能跑通示例”的薄封装，而是把前 5 个阶段已经形成的 QUIC transport、TLS、恢复、流和迁移能力，提升成可长期验证、可定位、可与外部实现对齐的产品级栈。当前仓库内的 `rfc-docs/` 只覆盖 RFC 9000、9001、9002、9369，因此本阶段与 QUIC transport/TLS/recovery 相关的行为仍以这些文档为基线；如果进入 HTTP/3/QPACK 子阶段，则应先把对应 RFC 文本补入仓库，再开始实现。

##### 1. 设计边界

- 本阶段优先交付“稳定的应用层接入能力 + 可观测性 + 互操作验证”，不要把新的 transport 特性和应用层集成混在同一轮里推进。
- 应先区分两个子目标，而不是直接把“接 HTTP/3”当成唯一选项：
  - 子阶段 A：基于现有 QUIC stream API 做一个稳定的应用层 demo，证明对外接口、错误处理、关闭路径和长连接收发已经可用。
  - 子阶段 B：在子阶段 A 稳定后，再评估引入 HTTP/3 所需的 RFC、控制流、QPACK 和互操作矩阵。
- 阶段 6 不应继续大幅改写阶段 4/5 的协议主体；如果发现 transport 层缺口，应先回补相应阶段的完成条件，再继续往应用层堆功能。
- 可观测性、fuzzing 和 interop 不是“收尾可选项”，而是本阶段完成定义的一部分；缺少这些能力时，即使 demo 能跑，也不能算完整 QUIC 栈。

##### 2. 建议的模块划分

- 在 transport 之上明确一层稳定的应用接口，至少抽象出：
  - 连接创建与销毁
  - 打开 stream / 接收 stream 事件
  - 发送数据、读取数据、发送 FIN、接收 RESET/STOP_SENDING
  - 连接级错误、流级错误、迁移/关闭事件回调
- 不要让 `example/client.c` / `example/server.c` 继续直接承担“协议核心 + 应用流程 + 调试脚本出口”三种职责。建议拆分出：
  - `src/app/`：最小应用接入层或 demo 协议层
  - `include/quic_api.h`：面向应用的稳定接口
  - `src/observe/`：qlog、metrics、调试事件导出
  - `tests/fuzz/`：面向包解析、frame 解析、stream 重组和状态机的 fuzz harness
- 如果后续进入 HTTP/3，建议再单独拆：
  - `src/http3/`
  - `include/http3.h`
  - `tests/interop/`

##### 3. 推荐的实现顺序

1. 先稳定对外 API，而不是先做 HTTP/3：
   - 明确应用如何创建连接、如何轮询事件、如何读写流、如何感知 close/timeout/migration。
   - 明确哪些错误属于连接错误，哪些只影响单个流。
2. 在稳定 API 之上实现一个可长期回归的应用层 demo：
   - 最小请求/响应协议，或更完整的文件传输/命令响应 demo。
   - 必须覆盖双向 stream、多个并发 stream、优雅关闭与错误关闭。
3. 再补可观测性：
   - qlog 风格事件
   - 关键指标导出：RTT、cwnd、bytes in flight、PTO 次数、丢包次数、流控阻塞次数、迁移事件
   - 自动化失败时保留足够高信号的状态输出
4. 再补 fuzzing：
   - 包头解析
   - frame 解析
   - transport parameters 编解码
   - ACK range 处理
   - stream 重组与 final size 相关状态机
5. 最后补 interop：
   - 先做“我方 client/外部 server”和“外部 client/我方 server”的 smoke test
   - 再做带文件传输或多 stream 的更强互通测试
6. 只有在上述能力稳定后，才进入 HTTP/3：
   - 先引入所需 RFC 文本
   - 再增加控制流、单向流、QPACK 与 HTTP/3 错误码

##### 4. 测试设计

阶段 6 建议仍按 3 层验证，不要只依赖一次 `topo.py`。

第一层：面向应用 API 和关闭语义的单元/集成测试，建议新增 `tests/test_phase21.c`

- 验证应用接口的最小稳定语义：
  - 打开双向和单向 stream 的返回值与状态变化
  - 应用读到 `FIN` 后的终态
  - `RESET_STREAM` / `STOP_SENDING` 传递到应用层的可见行为
  - 应用主动关闭连接与被动收到 `CONNECTION_CLOSE` 的差异
  - 迁移、idle timeout、stateless reset 事件是否能以一致的方式上报给应用

第二层：可观测性与 fuzzing 回归，建议新增 `tests/test_phase22.c`

- qlog/metrics 至少要验证：
  - 握手完成
  - stream 打开/关闭
  - ACK / loss / PTO
  - flow-control-limited
  - path validation / migration
  - connection close
- fuzzing 入口至少应覆盖：
  - 长头/短头包头解析
  - frame 解码
  - transport parameters
  - ACK range
  - CRYPTO / STREAM 重组
- 如果暂时没有引入真正的 libFuzzer，也应先用定制回归输入集做“准 fuzz”解析压力测试。

第三层：真实网络与互操作验证，建议新增 `tests/test_phase23.c` 与 `topo.py` 的 stage6 profile

- 这里不只验证“我方 client/server 彼此可通”，还要覆盖：
  - 长时间 bulk 传输中的稳定性
  - 多 stream 并发请求/响应
  - 迁移后继续执行业务流量
  - 关闭、超时、错误码与日志/指标的一致性
  - 与至少一种外部实现的基本握手和数据收发互通
- 互操作验证应明确区分：
  - transport 互通
  - 应用层 demo 互通
  - HTTP/3 互通（如果本阶段后半引入）

##### 5. 是否需要改动网络拓扑

阶段 6 不一定需要比阶段 5 更复杂的基础拓扑，但测试维度要更丰富。

- 对应用层 demo、qlog 和 metrics 验证，当前两主机拓扑仍然足够。
- 对 interop，`topo.py` 需要允许：
  - 只启用稳定 path，避免把 interop 问题和迁移问题混在一起
  - 配置更长的持续传输时间和更大的文件
  - 选择不同 profile：稳定链路、轻度丢包链路、迁移链路
- 如果后续要测 HTTP/3 或更真实的应用行为，再考虑新增：
  - 第三主机产生 cross traffic
  - 反向流量更强的双向请求/响应模式

##### 6. 推荐的 stage6 profile 与流量特征

建议至少准备以下 profile：

- `app-demo-clean`：
  - 无丢包、稳定 RTT，用于验证应用接口和业务收发逻辑本身。
- `app-demo-lossy`：
  - 低到中等丢包，用于验证应用层不会把恢复期误判为协议失败。
- `interop-clean`：
  - 稳定链路，优先排查互操作协议差异。
- `interop-migration`：
  - 在 transport 互通已经稳定后，再验证迁移事件不会打断应用层。

阶段 6 的流量特征不应再局限于单次上传/下载：

- 长连接上的多轮请求/响应
- 至少两个并发 stream 的双向业务数据
- 应用层主动关闭与异常关闭
- 迁移发生前后同一业务会话持续收发
- 如果进入 HTTP/3，则增加控制流、请求流、响应体和头阻塞相关场景

##### 7. 文档与脚本同步要求

- `README.md` 需要同步维护：
  - 对外 API 简介
  - 示例运行方式
  - qlog/metrics/fuzzing/interop 的验证入口
  - 当前已支持的应用层能力和未支持能力
- `topo.py` 需要预留 stage6 参数，例如：
  - `--app-mode`
  - `--interop-peer`
  - `--transfer-size`
  - `--request-count`
  - `--enable-qlog`
- 现有 `topo.py` 的 stage4/stage5/stage6 profile 需要继续保留；如果 interop 或 benchmark 需要更重的网络编排，应优先新增独立 topo 脚本，而不是覆写已稳定的入口。
- `example/` 不应只输出一句“成功/失败”，而要在失败时给出对应用层和 transport 层都有帮助的高信号状态。
- 阶段 6 完成前，README 中“已完成能力”不应提前宣称“HTTP/3 已实现”或“已完成全面互操作”；只有 `test_phase21/22/23` 与对应 `topo.py` profile、至少一种外部实现的互通验证稳定通过后，才能把这一阶段标记为完成。
