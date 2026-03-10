#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def run_quic_test_network():
    # 设置日志级别为 info，以便查看网络启动过程
    setLogLevel('info')

    info('*** 创建受控的 QUIC 测试网络 ***\n')
    # 使用 TCLink 以支持带宽、延迟和丢包率的设置
    net = Mininet(controller=Controller, switch=OVSKernelSwitch, link=TCLink)

    info('*** 添加控制器 ***\n')
    net.addController('c0')

    info('*** 添加交换机 ***\n')
    s1 = net.addSwitch('s1')

    info('*** 添加主机 (模拟 QUIC 客户端和服务端) ***\n')
    # h1 作为 QUIC Client
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    # h2 作为 QUIC Server
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')

    info('*** 创建带有网络特性的链路 ***\n')
    # 设置带宽 100Mbps，延迟 20ms，丢包率 2%（用来触发 QUIC 的 PTO 和 NewReno 拥塞控制）
    net.addLink(h1, s1, bw=100, delay='20ms', loss=2, use_htb=True)
    # 服务端链路也增加一点基础延迟
    net.addLink(h2, s1, bw=100, delay='10ms', use_htb=True)

    info('*** 启动网络 ***\n')
    net.start()

    info('*** 开启 Mininet CLI 进行交互测试 ***\n')
    CLI(net)

    info('*** 停止网络 ***\n')
    net.stop()

if __name__ == '__main__':
    run_quic_test_network()

# ==========================================
# 简易 QUIC 测试网络拓扑 (Mininet)
# ==========================================
#
#   [ h1: QUIC Client ]           [ h2: QUIC Server ]
#     IP: 10.0.0.1                  IP: 10.0.0.2
#          |                             |
#          | (20ms 延迟, 2% 丢包)        | (10ms 延迟)
#          |                             |
#          +---------- [ s1 ] -----------+
#                    (交换机)
#
# 总计: 端到端 RTT 约 60ms，单向丢包率 2%
# ==========================================