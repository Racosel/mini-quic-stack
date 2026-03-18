# AI-QUIC

`AI-QUIC` 是一个面向学习和分阶段实现的 QUIC 协议实验仓库。当前代码已经完成阶段 0、阶段 1、阶段 2 和阶段 3：除 QUIC v1/v2 的报文解析、Initial 密钥派生、Initial 报文保护/解保护、传输参数处理、最小化 ACK 与在途包管理外，还补上了基于 BoringSSL 的 TLS 1.3 QUIC 回调层、CRYPTO 数据重组、transport parameters 注入与解析、Handshake/0-RTT/1-RTT/短头包的真实收发、ACK 生成、Version Negotiation/Retry 运行时处理、服务端放大攻击限制，以及多流状态管理与基础流控。项目仍然不是完整的 QUIC 协议栈，更接近“协议构件验证平台”。

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
| 最小端到端多流示例 | UDP server/client 建立加密 QUIC 连接、在两个 bidirectional stream 上双向收发应用数据，并交换 1-RTT PING | RFC 9000, RFC 9001 | `example/server.c`, `example/client.c`, `topo.py` | `tests/test_phase12.c`, `tests/test_phase13.c`, `tests/test_phase14.c`, `make quic-demo` |

### 部分实现功能

以下能力已有“骨架”或“语法层支持”，但与 RFC 的完整要求相比仍不完整。

- 帧处理目前主要是“可遍历、可跳过、可抽取少量关键字段”，并未对大多数帧建立完整状态机或副作用。
- `quic_conn_recv_initial()` 与 `quic_tls_conn_handle_datagram()` 已能处理 ACK、CRYPTO、PING、HANDSHAKE_DONE、NEW_TOKEN、STREAM、RESET_STREAM、STOP_SENDING、MAX_DATA、MAX_STREAM_DATA、MAX_STREAMS 等关键帧，但没有对各包级别的合法帧集合做完整约束，也没有接入 blocked/path/CID 管理等剩余控制帧状态机。
- 传输参数虽然支持编解码多个标准字段，但缺少默认值补齐、语义合法性校验和跨字段约束检查。
- Version Negotiation 与 Retry 已串进真实收发流程，但仍缺少降级防护、兼容版本协商和更完整的 token/地址验证策略。
- 0-RTT 已具备包级解析/构造路径，但仍未接入真实应用数据、重放风险约束和会话票据语义。
- ACK/恢复模块只实现了最小 in-flight bookkeeping；虽然连接层已有统一定时器入口，但尚未实现 RTT 估计、丢包检测、PTO 或拥塞控制。

### 尚未实现功能

与 RFC 9000/9001/9002/9369 相比，当前仓库明显缺失以下核心能力：

- 连接迁移、路径验证、CID 生命周期管理与 NEW_CONNECTION_ID 语义执行
- Stateless Reset 构造与处理
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
- `test13`: 阶段 2 完整包收发管线，覆盖 ACK 生成、交错时序下的后续 Initial、Retry、Version Negotiation、放大攻击限制、0-RTT 与短头包路径
- `test14`: 阶段 3 流与流控基础，覆盖多流双向数据传输、MAX_DATA/MAX_STREAM_DATA 增长，以及 STOP_SENDING 触发 RESET_STREAM

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

## 当前定位

如果你的目标是“完整 QUIC 协议栈”，这个仓库仍处于早期构件验证阶段；如果你的目标是“逐模块验证 QUIC 关键部件并继续演进”，当前结构已经适合作为后续扩展的基础。

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

阶段 5：实现连接管理与迁移能力。补齐 CID 生命周期、NEW_CONNECTION_ID/RETIRE_CONNECTION_ID 语义、path validation、connection migration、preferred_address、stateless reset、idle timeout、close/error handling、token 与地址验证。完成标志是连接不仅能“建立和传数据”，还能正确处理迁移、关闭和异常路径。

阶段 6：接应用层与做互操作收尾。最后再接 HTTP/3 或至少一个稳定的应用层 demo，补 qlog/metrics/fuzzing/interop tests，和 quiche、ngtcp2、msquic 这类实现做互通验证。完成标志是仓库不再只是协议构件集合，而是一个可对外使用、可验证、可调试的完整 QUIC 栈。

如果你要更可执行一点，我下一步可以把这 7 个阶段继续展开成“每阶段需要新增哪些 .c/.h 文件、哪些测试目标、哪些 RFC 小节对应到哪些实现任务”的开发计划。
