---
name: ai-quic-stage-guide
description: 维护 AI-QUIC 仓库时使用的项目级工作记忆，覆盖当前阶段能力、强制日志规则、关键文件、构建与验证入口，以及继续补全 QUIC 协议栈时的实现边界。
---

# AI-QUIC 阶段开发指南

## 何时使用

当任务涉及以下任一内容时，使用本 skill：

- 继续实现 AI-QUIC 的后续阶段能力
- 修改阶段 0 或阶段 1 的连接、TLS、CRYPTO、示例或测试代码
- 对照 RFC 9000、9001、9002、9369 审查当前实现状态
- 补测试、补 README、补 example 或补拓扑验证

## 快速开始

1. 先阅读仓库根目录的 `README.md`，确认当前阶段、功能矩阵和缺失项。
2. 检查根目录 `log` 是否存在；如果不存在，先创建。
3. 检查根目录 `debug` 是否存在；如果不存在，先创建。
4. 每执行一个步骤，都向根目录 `log` 追加记录。
5. 每次追加日志前，都重新获取当前时间，不能复用任务开始时或上一条日志的时间戳。
6. 每当发现 bug、确认根因、实施修复或完成验证时，都向根目录 `debug` 实时追加记录，至少写明现象、影响、定位结论、修复方法和验证结果。
7. 本仓库中的说明、skill、README 和新增注释默认使用中文；协议名、宏名、函数名、RFC 术语和外部接口名保持英文。
8. 任何“已实现功能”的新增或重构，都要同步补测试，并实际运行相关测试。
9. 如果行为、阶段状态、验证方式或功能矩阵发生变化，同步更新 `README.md`。

## 协议基线

- 主要参照 RFC 9000、RFC 9001、RFC 9002、RFC 9369。
- 本项目当前并不以 RFC 9003 作为 QUIC 协议基线，因为 RFC 9003 不是 QUIC 标准。
- 如果后续引入额外扩展，先在 `README.md` 中说明对应 RFC 或草案，再开始实现。

## 当前阶段结论

### 阶段 0：已完成

连接层已经从“只够处理 Initial 接收”的单点逻辑，重构为统一骨架：

- 显式连接状态机
- `Initial`、`Handshake`、`Application Data` 三类包号空间
- 统一收包入口
- 统一发包计划入口
- 统一定时器与事件入口

关键文件：

- `include/quic_connection.h`
- `src/transport/quic_connection.c`
- `tests/test_phase11.c`

### 阶段 1：已完成

TLS 1.3 与 QUIC 握手核心已经落地：

- 接入 BoringSSL 的 `SSL_QUIC_METHOD`
- 支持 CRYPTO 数据重组
- 支持 transport parameters 注入与解析
- 支持 Handshake 密钥和 1-RTT 密钥安装
- 支持 Initial / Handshake 旧密钥丢弃
- 支持最小化握手 flight 定时重传
- 支持最小化 1-RTT 短头包 PING 验证路径

关键文件：

- `include/quic_tls.h`
- `src/tls/quic_tls.c`
- `include/quic_crypto_stream.h`
- `src/transport/quic_crypto_stream.c`
- `tests/test_phase12.c`
- `example/server.c`
- `example/client.c`
- `topo.py`

## 当前仓库的重要能力

- QUIC v1 / v2 长短头预解析与版本分派
- Initial 密钥派生
- Initial 报文保护 / 解保护
- Retry 完整性标签计算与校验
- transport parameters 编解码
- ACK 语法解析与最小在途包管理
- 连接级 Initial 接收路径
- 分包号空间的连接骨架
- 基于 BoringSSL 的 QUIC/TLS 握手核心
- 最小端到端 QUIC client / server 示例

## 当前仓库仍然缺失的主体能力

这些内容仍然属于后续阶段，不要误判为“已完成”：

- 0-RTT 数据路径
- 更完整的 Handshake / 1-RTT 收发管线
- ACK 生成与完整重传队列
- 流状态机、流控和发送调度
- RFC 9002 主体：RTT、PTO、loss detection、拥塞控制
- 连接迁移、CID 生命周期、路径验证、stateless reset
- Key Update
- 应用层协议集成，例如 HTTP/3

## 关键实现约束

- 连接级逻辑优先挂到统一骨架上，不要重新散落到单独的 Initial 专用路径。
- 涉及密钥生命周期的改动，必须显式说明属于哪个包号空间、哪个方向、何时安装、何时丢弃。
- CRYPTO 数据必须先重组，再交给 TLS 层。
- transport parameters 的原始字节通过 TLS 传递，语义解析仍由 QUIC 代码负责。
- 如果增加新的“已实现功能”，必须新增测试或扩展现有测试，不能只改代码不补覆盖。
- 如果新增 example、握手路径或拓扑验证逻辑，要同步检查 `Makefile` 和 `README.md`。
- `log` 用于记录执行步骤；`debug` 用于记录 bug、根因、修复方法和验证结果，这两者不能互相替代。

## BoringSSL 集成要点

- 本项目使用仓库根目录下的 `boringssl/`。
- 头文件来自 `boringssl/include`。
- 静态库由以下目标生成：
  - `boringssl/build/libssl.a`
  - `boringssl/build/libcrypto.a`
- 当前 `Makefile` 已经把仓库代码链接到 BoringSSL，并附带 `-lpthread -ldl -lstdc++`。
- 涉及 QUIC/TLS 交互时，优先围绕以下接口检查实现：
  - `SSL_QUIC_METHOD`
  - `SSL_provide_quic_data`
  - `SSL_process_quic_post_handshake`
  - `SSL_set_quic_transport_params`
  - `SSL_get_peer_quic_transport_params`

## 标准验证入口

### 单元与阶段测试

优先运行与改动最相关的目标；如果改动影响连接层或 TLS 层，至少覆盖以下集合：

```bash
make test10
make test11
make test12
```

如果改动波及更底层的包处理、恢复或 transport parameters，扩展为：

```bash
make test1 test2 test3 test4 test5_1 test6 test7 test8 test9 test10 test11 test12
```

### 示例构建

```bash
make quic-demo
```

该目标会构建：

- `example/quic_server`
- `example/quic_client`

并在需要时生成：

- `example/server_cert.pem`
- `example/server_key.pem`

### 拓扑验证

如果机器具备 root 权限并已安装 Mininet，使用：

```bash
make topo-auto
```

注意：

- `topo.py --auto` 依赖 root 权限
- 如果缺少 root 或 `sudo` 口令，拓扑验证无法在当前会话内自动完成
- 这种情况下，至少完成 `test12` 和 `make quic-demo` 作为最小回归

## 后续阶段工作方式

继续推进阶段 2 及以后时，建议固定使用以下顺序：

1. 在 `README.md` 明确该阶段目标和完成标志。
2. 先补连接骨架所需的数据结构和接口，再挂接具体收发行为。
3. 实现后立即补测试，优先做内存内或最小本地回环验证。
4. 如果功能需要真实网络路径，再补 `example/` 和 `topo.py` 验证。
5. 完成后更新 `README.md`、`log` 和相关注释。

## 参考文件

- `README.md`
- `Makefile`
- `topo.py`
- `tests/test_phase11.c`
- `tests/test_phase12.c`
- `example/server.c`
- `example/client.c`
- `src/transport/quic_connection.c`
- `src/tls/quic_tls.c`
- `src/transport/quic_crypto_stream.c`
