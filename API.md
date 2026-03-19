# AI-QUIC 对外 API

本文档描述当前仓库面向应用层暴露的稳定 API。当前 API 位于 `include/quic_api.h`，实现位于 `src/app/quic_api.c`。这一层的目标是把 `quic_tls` 的内部状态机包装成更适合应用接入、观测和测试的接口。

边界说明：

- 当前 API 面向 QUIC transport 层与最小应用示例，不包含 HTTP/3。
- 当前 API 已覆盖连接创建、收发、stream 读写、迁移入口、关闭入口、事件、metrics 和只读快照。
- 当前 API 不负责 interop、HTTP/3、QPACK，也不保证和内部 `quic_tls` 一样细的实现细节稳定暴露。

## 1. 头文件与核心对象

- 头文件：`include/quic_api.h`
- 核心连接对象：`quic_api_conn_t`
- 典型使用顺序：
  1. `quic_api_conn_init()`
  2. `quic_api_conn_set_initial_flow_control()` / `quic_api_conn_set_max_idle_timeout()` 等配置
  3. `quic_api_conn_configure()`
  4. `quic_api_conn_set_initial_path()`
  5. `quic_api_conn_start()`
  6. 循环调用：
     - `quic_api_conn_handle_datagram_on_path()`
     - `quic_api_conn_build_next_datagram_on_path()`
     - `quic_api_conn_on_timeout()`
     - `quic_api_conn_poll_event()`
  7. `quic_api_conn_close()`
  8. `quic_api_conn_free()`

## 2. 主要数据结构

### `quic_api_event_t`

面向事件队列的最小事件对象，字段包括：

- `sequence`：单连接内递增事件序号
- `time_ms`：单调时钟毫秒时间
- `type`：事件类型
- `stream_id`：关联 stream，没有则为 `UINT64_MAX`
- `path_index`：关联 path 索引
- `value_u64`：附带数值，按事件类型解释
- `state`：事件产生时的连接状态

当前事件类型：

- `QUIC_API_EVENT_CONNECTION_STARTED`
- `QUIC_API_EVENT_HANDSHAKE_COMPLETE`
- `QUIC_API_EVENT_STREAM_OPENED`
- `QUIC_API_EVENT_STREAM_READABLE`
- `QUIC_API_EVENT_STREAM_FIN_RECEIVED`
- `QUIC_API_EVENT_PATH_VALIDATED`
- `QUIC_API_EVENT_ACTIVE_PATH_CHANGED`
- `QUIC_API_EVENT_PING_QUEUED`
- `QUIC_API_EVENT_CONNECTION_CLOSE_REQUESTED`
- `QUIC_API_EVENT_CONNECTION_STATE_CHANGED`
- `QUIC_API_EVENT_CONNECTION_CLOSED`

### `quic_api_metrics_t`

当前暴露的基础指标：

- `bytes_sent`
- `bytes_received`
- `bytes_in_flight`
- `congestion_window`
- `latest_rtt_ms`
- `smoothed_rtt_ms`
- `pto_count`
- `events_emitted`
- `events_dropped`
- `streams_opened_local`
- `streams_opened_remote`
- `fin_streams_received`
- `connections_closed`
- `active_streams`
- `path_count`
- `active_path_index`

### `quic_api_conn_info_t`

连接级只读快照：

- `role`
- `state`
- `handshake_complete`
- `application_secrets_ready`
- `has_pending_output`
- `close_received`
- `close_sent`
- `stateless_reset_detected`
- `ping_received`
- `path_count`
- `active_path_index`
- `pending_path_index`

### `quic_api_path_info_t`

path 级只读快照：

- `present`
- `state`
- `local`
- `peer`
- `bytes_received`
- `bytes_sent_before_validation`
- `challenge_pending`
- `challenge_in_flight`
- `challenge_expected`
- `response_pending`
- `response_in_flight`
- `mtu_validated`

### `quic_api_stream_info_t`

stream 级只读快照：

- `exists`
- `local_initiated`
- `bidirectional`
- `send_open`
- `recv_open`
- `fin_sent`
- `fin_received`
- `reset_received`
- `stop_sending_received`
- `readable_bytes`
- `send_highest_offset`
- `recv_highest_offset`
- `recv_final_size_known`
- `recv_final_size`

## 3. 生命周期与配置接口

| 函数 | 功能 | 返回值 |
| --- | --- | --- |
| `quic_api_conn_init(quic_api_conn_t *conn)` | 初始化对外 API 连接对象。 | 无。 |
| `quic_api_conn_free(quic_api_conn_t *conn)` | 释放连接对象持有的 TLS、流、事件和缓冲区资源。 | 无。 |
| `quic_api_conn_configure(...)` | 配置角色、版本、CID，以及服务端证书/私钥。客户端证书参数传 `NULL`。 | `0` 成功；`< 0` 表示参数非法、版本不支持或 TLS/QUIC 初始化失败。 |
| `quic_api_conn_enable_retry(quic_api_conn_t *conn, int enabled)` | 开启或关闭 Retry 逻辑。 | 无。 |
| `quic_api_conn_set_max_idle_timeout(quic_api_conn_t *conn, uint64_t timeout_ms)` | 设置本端声明的最大 idle timeout。 | 无。 |
| `quic_api_conn_set_initial_flow_control(...)` | 设置连接和 stream 的初始流控参数。 | 无。 |
| `quic_api_conn_set_initial_path(quic_api_conn_t *conn, const quic_path_addr_t *path)` | 设置连接的初始 path。 | `0` 成功；`< 0` 表示 path 非法或状态不允许。 |
| `quic_api_conn_set_server_preferred_address(...)` | 在服务端连接上配置待通告给客户端的 preferred address。 | `0` 成功；`< 0` 表示参数非法、CID/token 不合法或状态不允许。 |
| `quic_api_conn_get_peer_preferred_address(...)` | 读取对端 transport parameters 中的 preferred address。 | `0` 成功；`< 0` 表示当前没有可用 preferred address 或输出参数无效。 |
| `quic_api_conn_begin_migration(quic_api_conn_t *conn, const quic_path_addr_t *path, int use_preferred_address)` | 请求开始一次主动迁移或 preferred-address 迁移。 | `0` 成功；`< 0` 表示状态不允许、path 非法或迁移前提未满足。 |
| `quic_api_conn_start(quic_api_conn_t *conn)` | 启动连接。客户端会开始发送 Initial；服务端则进入可接收/可处理状态。 | `0` 成功；`< 0` 表示连接尚未配置完成或启动失败。 |

## 4. 收发与定时器接口

| 函数 | 功能 | 返回值 |
| --- | --- | --- |
| `quic_api_conn_handle_datagram(quic_api_conn_t *conn, const uint8_t *packet, size_t packet_len)` | 在默认 path 上处理一个入站 datagram。 | `0` 成功；`< 0` 表示解包、密钥或状态机处理失败。 |
| `quic_api_conn_handle_datagram_on_path(quic_api_conn_t *conn, const uint8_t *packet, size_t packet_len, const quic_path_addr_t *path)` | 在显式 path 上处理一个入站 datagram。建议优先用这一版。 | `0` 成功；`< 0` 表示 path 非法、解包失败或状态机拒绝该数据报。 |
| `quic_api_conn_build_next_datagram(quic_api_conn_t *conn, uint8_t *out, size_t out_len, size_t *written)` | 在默认 path 上构造下一个待发送 datagram。 | `0` 成功；`QUIC_TLS_BUILD_BLOCKED` 表示暂时受发送约束阻塞；其他非零表示错误。 |
| `quic_api_conn_build_next_datagram_on_path(quic_api_conn_t *conn, uint8_t *out, size_t out_len, size_t *written, quic_path_addr_t *out_path)` | 构造下一个待发送 datagram，并返回目标 path。 | `0` 成功；`QUIC_TLS_BUILD_BLOCKED` 表示暂时受发送约束阻塞；其他非零表示错误。 |
| `quic_api_conn_has_pending_output(const quic_api_conn_t *conn)` | 判断当前是否仍有待发送输出。 | 非 `0` 表示仍有输出；`0` 表示没有。 |
| `quic_api_conn_on_timeout(quic_api_conn_t *conn, uint64_t now_ms)` | 在给定时间点推进统一超时逻辑。 | 无。 |
| `quic_api_conn_next_timeout_ms(const quic_api_conn_t *conn)` | 查询下一次需要调用 `quic_api_conn_on_timeout()` 的绝对时间。 | 绝对时间毫秒值；`0` 表示当前没有定时器。 |

## 5. 只读快照接口

| 函数 | 功能 | 返回值 |
| --- | --- | --- |
| `quic_api_conn_get_info(const quic_api_conn_t *conn, quic_api_conn_info_t *out_info)` | 读取连接级只读快照。 | `0` 成功；`< 0` 表示输出参数无效。 |
| `quic_api_conn_get_path_info(const quic_api_conn_t *conn, size_t path_index, quic_api_path_info_t *out_info)` | 读取某条 path 的只读快照。 | `0` 成功；`< 0` 表示 path 索引越界或输出参数无效。 |
| `quic_api_conn_get_stream_info(const quic_api_conn_t *conn, uint64_t stream_id, quic_api_stream_info_t *out_info)` | 读取指定 stream 的只读快照。 | `0` 表示调用成功；若流不存在则 `out_info->exists == 0`；`< 0` 表示输出参数无效。 |
| `quic_api_conn_raw(const quic_api_conn_t *conn)` | 返回底层 `quic_tls_conn_t` 指针，供调试或过渡阶段查看内部状态。 | 非 `NULL` 表示有效底层连接；`NULL` 表示输入连接无效。 |

## 6. Stream 接口

| 函数 | 功能 | 返回值 |
| --- | --- | --- |
| `quic_api_conn_open_stream(quic_api_conn_t *conn, int bidirectional, uint64_t *stream_id)` | 打开一个新的本地 stream。 | `0` 成功；`< 0` 表示流数量限制、状态不允许或参数无效。 |
| `quic_api_conn_stream_write(quic_api_conn_t *conn, uint64_t stream_id, const uint8_t *data, size_t len, int fin)` | 向指定 stream 写入数据，并可附带 FIN。 | `0` 成功；`< 0` 表示流不存在、流控受限或状态不允许。 |
| `quic_api_conn_stream_read(quic_api_conn_t *conn, uint64_t stream_id, uint8_t *out, size_t out_cap, size_t *out_read, int *out_fin)` | 从指定 stream 读取数据。 | `0` 成功；`< 0` 表示流不存在、输出参数无效或状态不允许。 |
| `quic_api_conn_stream_peek(const quic_api_conn_t *conn, uint64_t stream_id, size_t *available, int *fin, int *exists)` | 查看指定 stream 当前可读字节数和 FIN 状态，但不消费数据。 | `0` 成功；`< 0` 表示输出参数无效。 |
| `quic_api_conn_stop_sending(quic_api_conn_t *conn, uint64_t stream_id, uint64_t error_code)` | 向对端发送 STOP_SENDING 请求。 | `0` 成功；`< 0` 表示流不存在或当前状态不允许。 |
| `quic_api_conn_reset_stream(quic_api_conn_t *conn, uint64_t stream_id, uint64_t error_code)` | 向对端发送 RESET_STREAM。 | `0` 成功；`< 0` 表示流不存在或当前状态不允许。 |

## 7. 连接控制与状态接口

| 函数 | 功能 | 返回值 |
| --- | --- | --- |
| `quic_api_conn_queue_ping(quic_api_conn_t *conn)` | 排队一个待发送的 PING。 | 无。 |
| `quic_api_conn_close(quic_api_conn_t *conn, uint64_t transport_error_code)` | 请求发送 `CONNECTION_CLOSE`。 | `0` 成功；`< 0` 表示当前状态不允许或构包失败。 |
| `quic_api_conn_handshake_complete(const quic_api_conn_t *conn)` | 判断握手是否已经完成。 | 非 `0` 表示已完成；`0` 表示未完成。 |
| `quic_api_conn_last_error(const quic_api_conn_t *conn)` | 返回最近一次 API/TLS 层错误文本。 | 始终返回可读字符串；输入连接无效时返回兜底错误文本。 |

## 8. 观测接口

### 事件

| 函数 | 功能 | 返回值 |
| --- | --- | --- |
| `quic_api_conn_poll_event(quic_api_conn_t *conn, quic_api_event_t *out_event)` | 从事件队列中弹出一个事件。 | `0` 表示成功取到事件；`< 0` 表示当前没有事件或参数无效。 |
| `quic_api_event_name(quic_api_event_type_t type)` | 返回事件类型对应的人类可读名称。 | 始终返回静态字符串。 |
| `quic_api_event_format_json(const quic_api_event_t *event, char *out, size_t out_cap)` | 把事件格式化为 qlog 风格 JSON 行。 | `0` 成功；`< 0` 表示输出缓冲区不足或参数无效。 |

当前输出的是“qlog 风格 JSON 事件行”，用于 demo 和测试日志，不等价于完整 qlog schema。

### 指标

| 函数 | 功能 | 返回值 |
| --- | --- | --- |
| `quic_api_conn_get_metrics(quic_api_conn_t *conn, quic_api_metrics_t *out_metrics)` | 读取当前 metrics 快照。 | `0` 成功；`< 0` 表示输出参数无效。 |
| `quic_api_metrics_format_json(const quic_api_metrics_t *metrics, char *out, size_t out_cap)` | 把 metrics 快照格式化为 JSON。 | `0` 成功；`< 0` 表示输出缓冲区不足或参数无效。 |

## 9. 最小使用示例

```c
quic_api_conn_t conn;
quic_api_event_t event;
quic_api_metrics_t metrics;

quic_api_conn_init(&conn);
quic_api_conn_set_initial_flow_control(&conn, 128 * 1024, 64 * 1024, 64 * 1024, 64 * 1024, 8, 8);
quic_api_conn_configure(&conn, QUIC_ROLE_CLIENT, QUIC_V1_VERSION, &scid, &odcid, NULL, NULL);
quic_api_conn_set_initial_path(&conn, &path);
quic_api_conn_start(&conn);

while (running) {
    if (quic_api_conn_has_pending_output(&conn)) {
        quic_api_conn_build_next_datagram_on_path(&conn, packet, sizeof(packet), &written, &send_path);
        send_udp(packet, written, &send_path);
    }
    if (recv_udp(packet, &packet_len, &recv_path) == 0) {
        quic_api_conn_handle_datagram_on_path(&conn, packet, packet_len, &recv_path);
    }
    if (timeout_due) {
        quic_api_conn_on_timeout(&conn, now_ms);
    }
    while (quic_api_conn_poll_event(&conn, &event) == 0) {
        char line[256];

        quic_api_event_format_json(&event, line, sizeof(line));
        puts(line);
    }
}

quic_api_conn_get_metrics(&conn, &metrics);
quic_api_conn_free(&conn);
```

## 10. 当前验证入口

- API/关闭语义：`make test21`
- 事件/metrics 与准 fuzz 回归：`make test22`
- 独立 fuzz smoke harness：`make fuzz-smoke`
- app demo loopback：`make test23`
- app demo 二进制：`make quic-app-demo`

## 11. 当前未覆盖范围

- interop
- HTTP/3 / QPACK
- libFuzzer / sanitizer 级 fuzzing
- Key Update
- 完整 0-RTT / resumption / ticket 生命周期
