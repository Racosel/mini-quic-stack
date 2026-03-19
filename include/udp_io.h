#ifndef UDP_IO_H
#define UDP_IO_H

// 功能：初始化 UDP 批量接收资源。
// 返回值：无。
void udp_io_init();

// 功能：执行批量接收并调用预解析。
// 返回值：>= 0 表示成功接收的数据报数量；< 0 表示系统调用或解析阶段出错。
int udp_receive_batch(int udp_fd);

// 功能：返回上一轮批量接收中成功通过预解析的数据报数量。
// 返回值：>= 0 表示上一轮有效数据报数量。
int udp_last_valid_count(void);

#endif // UDP_IO_H：头文件保护结束
