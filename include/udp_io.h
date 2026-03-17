#ifndef UDP_IO_H
#define UDP_IO_H

// 初始化 UDP 批量接收资源
void udp_io_init();

// 执行批量接收并调用预解析
// 返回值：成功接收的数据报数量，< 0 表示出错
int udp_receive_batch(int udp_fd);

// 返回上一轮批量接收中，成功通过预解析的数据报数量
int udp_last_valid_count(void);

#endif // UDP_IO_H：头文件保护结束
