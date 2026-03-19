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
5. 每次追加日志前，都重新获取当前时间，不能复用任务开始时或上一条日志的时间戳；`log` 的时间格式固定为 `[%Y-%m-%d %H:%M:%S %z]`，前后使用英文中括号。
6. 每当发现 bug、确认根因、实施修复或完成验证时，都向根目录 `debug` 实时追加 Markdown 记录，至少写明时间、阶段、现象、影响、定位结论、修复方法和验证结果。
7. 每次收到用户贴回的运行结果，或自己从自动脚本中拿到输出时，都要先检查 `debug` 里的相关 bug 状态：已经确认解决的条目标记为“已解决”；如果同一个 bug 经过后续调整才彻底修好，就在原有 bug 条目里追加现象、分析、修复和验证过程，而不是默认新开一个替代 bug。
8. 代码重构或补实现时，在必要位置保留适量的逻辑说明、关键函数签名和有助于理解行为边界的描述，不要把关键语义信息在整理代码时一并删掉。
9. 本仓库中的说明、skill、README 和新增注释默认使用中文；协议名、宏名、函数名、RFC 术语和外部接口名保持英文。
10. 任何“已实现功能”的新增或重构，都要同步补测试，并实际运行相关测试。
11. 如果行为、阶段状态、验证方式或功能矩阵发生变化，同步更新 `README.md`。
12. 当发现代码行为可能有误，且该行为受 IETF 文档约束时，必须先到仓库内 `rfc-docs/` 查找对应 RFC 条款；若本地文件不足，再查官方 IETF/RFC 文本，确认规范要求后才能修改代码，不能凭印象修协议行为。
13. 当用户要求“执行某一阶段”时，以 `README.md` 中该阶段的缺失功能和完成标志作为唯一边界；实现、测试和结论都必须回到这些完成标志上核对，不能擅自缩小或扩大发散范围。
14. 所有测试使用的产物统一放在 `tests/` 下：测试二进制放在 `tests/bin/`，测试证书放在 `tests/certs/`，文件传输与其他临时测试数据放在 `tests/data/`。
15. 修改构建或验证脚本时，确保 `make clean` 能清掉除 `boringssl/build/` 之外的所有二进制和临时文件。
16. 自动化验证默认不能只跑 1 次；测试、示例回归和拓扑验证应默认重复执行 5 轮，除非用户明确要求更改轮数。
17. `Bug 008` 是一个已经修复、但仍需长期警惕的跨层耦合缺陷群。后续只要改动 `src/tls/quic_tls.c`、`src/transport/quic_stream.c`、`src/recovery/quic_ack.c`、`example/client.c`、`example/server.c`、`topo.py` 或阶段 12-14 相关测试，就必须假设可能重新引入耦合回归，并至少重跑 `make test12 test13 test14`、本机文件传输回环和 `make topo-auto-file`。
18. 对这类长期迭代的大 bug，`debug` 中最终应整理为高信号摘要，优先保留“现象、影响、主根因、修复、验证、后续风险”，不要无限追加流水账；具体执行时间线由 `log` 承担。
19. 当用户在本机测试或自动化脚本中贴回失败输出时，如果当前信息不足以定位问题，可以在 `example/`、测试或自动化脚本的失败/超时打印中临时补充高信号状态信息，便于下一轮调试；这些附加输出应优先打印路径状态、关键标志位、当前阶段和待发送/待验证状态，而不是泛泛增加噪声。
20. 阶段推进过程中，要及时更新 `README.md` 中与当前任务直接相关的内容，至少同步任务边界、当前完成度、验证方式和测试进度；不要把 README 更新拖到所有代码都结束之后再一次性补写。

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

### 阶段 2：已完成

完整包收发管线已经落地：

- 支持 Handshake、0-RTT、1-RTT、短头包的真实解析与构造
- 支持 ACK 自动生成与在途包清理
- 支持 Version Negotiation 与 Retry 进入真实收发流程
- 支持服务端放大攻击限制
- `example/` 与 Mininet 拓扑均已验证双方能建立加密 QUIC 连接并交换 1-RTT PING

关键文件：

- `src/tls/quic_tls.c`
- `src/packet/quic_version.c`
- `src/recovery/quic_ack.c`
- `src/recovery/loss_detector.c`
- `tests/test_phase13.c`
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
- 阶段 2 的完整包收发管线
- 最小端到端 QUIC client / server 示例

## 当前仓库仍然缺失的主体能力

这些内容仍然属于后续阶段，不要误判为“已完成”：

- 完整的 0-RTT 应用数据语义与重放约束
- 更完整的流帧 / 控制帧副作用处理
- 完整重传队列与恢复主体
- 流状态机、流控和发送调度
- RFC 9002 主体：RTT、PTO、loss detection、拥塞控制
- 连接迁移、CID 生命周期、路径验证、stateless reset
- Key Update
- 应用层协议集成，例如 HTTP/3

## 关键实现约束

- 新阶段实现前，先把 `README.md` 中对应阶段的目标、缺失项和完成标志重新读一遍，再决定改动边界。
- 连接级逻辑优先挂到统一骨架上，不要重新散落到单独的 Initial 专用路径。
- 涉及密钥生命周期的改动，必须显式说明属于哪个包号空间、哪个方向、何时安装、何时丢弃。
- CRYPTO 数据必须先重组，再交给 TLS 层。
- transport parameters 的原始字节通过 TLS 传递，语义解析仍由 QUIC 代码负责。
- 当怀疑协议行为不符合规范时，优先对照 `rfc-docs/9000`、`rfc-docs/9001`、`rfc-docs/9002`、`rfc-docs/9369` 中的相关条款，再动代码。
- 如果增加新的“已实现功能”，必须新增测试或扩展现有测试，不能只改代码不补覆盖。
- 如果阶段任务涉及握手、包收发管线或真实网络行为，除核心库代码外，还要同步维护 `example/server.c`、`example/client.c`、`topo.py` 与 `Makefile`，不能只做库内单元测试。
- 如果新增 example、握手路径或拓扑验证逻辑，要同步检查 `Makefile` 和 `README.md`。
- `log` 用于记录执行步骤；`debug` 用于记录 bug、根因、修复方法和验证结果，这两者不能互相替代。
- `log` 的每一条记录都必须使用 `date '+%Y-%m-%d %H:%M:%S %z'` 获取时间，并写成 `[时间] 内容` 的形式。
- `debug` 必须使用便于阅读的 Markdown 格式，优先按“时间、阶段、标题、现象、影响、根因、修复、验证、相关文件、状态”组织。
- 每次读取到新的运行输出后，先回看 `debug`：能确认解决的 bug 把状态改成“已解决”；同一 bug 的后续分析与最终修复继续写回原条目。
- 整理代码时不要机械删掉所有描述性内容；关键逻辑转折处应保留必要注释、函数签名和行为边界说明。
- `topo.py` 的自动化状态输出使用脚本自身的 `ERROR` / `DONE` 标识；如果继续修改自动化脚本，保持错误为红底、完成为绿底，便于从长日志中快速定位结果。
- 当用户在本机测试中遇到错误且现有输出不足以定位时，可以先增强失败/超时打印，再让用户复跑；增强输出应服务于下次调试闭环，而不是长期保留无结论的噪声。
- `README.md` 不只是收尾文档，也是阶段执行过程中的进度面板；任务边界、完成标志和测试进度有变化时，及时同步，不要滞后于实现太久。

## 历史高风险区域

- `Bug 008` 已经在用户侧完成 30 次 `make topo-auto-file` 复验，但它本质上是跨层耦合缺陷群，不是单一补丁。
- 该问题群覆盖：
- 连接关闭语义与显式应用完成信号
- `topo.py` 的服务端就绪竞态与测试数据管理
- ACK Range 与重传
- `STREAM + FIN` 后的发送侧状态机
- 终态流对合法重传的处理
- 应用空间 / Handshake 空间在读密钥未就绪时的乱序包处理
- anti-amplification 的阻塞语义与 loss timer
- 因此，后续若继续推进阶段 4 及以后内容，不要把这些区域当作“已经稳定、不需要联动回归”的普通代码。

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
make test13
```

对于握手、收发管线、example 或拓扑相关改动，不要停在“测试已写好”，而要在同一轮中自动执行这些目标。

如果改动波及更底层的包处理、恢复或 transport parameters，扩展为：

```bash
make test1 test2 test3 test4 test5_1 test6 test7 test8 test9 test10 test11 test12
make test13
```

### 示例构建

```bash
make quic-demo
```

该目标会构建：

- `tests/bin/quic_server`
- `tests/bin/quic_client`

并在需要时生成：

- `tests/certs/server_cert.pem`
- `tests/certs/server_key.pem`

### 拓扑验证

如果机器具备 root 权限并已安装 Mininet，使用：

```bash
make topo-auto
```

注意：

- `topo.py --auto` 依赖 root 权限
- 默认运行 5 轮；如需调整，使用 `python3 topo.py --auto --rounds <N>`
- 如果缺少 root 或 `sudo` 口令，拓扑验证无法在当前会话内自动完成
- 这种情况下，至少完成相关阶段测试和本机 `example/` 回环验证，再把 `sudo python3 topo.py --auto` 交给用户执行
- 用户返回拓扑输出后，要继续分析、定位、修改并让用户复验，而不是把拓扑验证永久留给用户自己消化

### 推荐验证顺序

对阶段 1、阶段 2 及后续所有涉及真实网络行为的任务，优先遵循以下顺序：

1. 先跑最相关的单元与阶段测试。
2. 再跑本机 `tests/bin/quic_server` / `tests/bin/quic_client` 回环验证。
3. 最后跑 `topo.py --auto` 或 `make topo-auto` 做 Mininet 拓扑验证。
4. 只有三层验证都覆盖到，且结果与 `README.md` 中的完成标志一致，才宣告该阶段完成。

## 后续阶段工作方式

继续推进阶段 2 及以后时，建议固定使用以下顺序：

1. 在 `README.md` 明确该阶段目标和完成标志。
2. 先补连接骨架所需的数据结构和接口，再挂接具体收发行为。
3. 实现后立即补测试，优先做内存内验证。
4. 若该阶段完成标志涉及真实连接、真实握手或真实收发，继续补 `example/` 并做本地回环验证。
5. 若该阶段完成标志涉及拓扑网络行为，再执行 `topo.py` 验证；当前环境受限时，让用户代跑并根据输出继续迭代。
6. 若验证输出里既有 warning 又有错误，先区分“环境噪声”和“协议故障”，再决定是否修改代码。
7. 完成后更新 `README.md`、`log` 和相关注释。

## 参考文件

- `README.md`
- `Makefile`
- `topo.py`
- `tests/bin/`
- `tests/certs/`
- `tests/data/`
- `tests/test_phase11.c`
- `tests/test_phase12.c`
- `tests/test_phase13.c`
- `example/server.c`
- `example/client.c`
- `src/transport/quic_connection.c`
- `src/tls/quic_tls.c`
- `src/transport/quic_crypto_stream.c`
