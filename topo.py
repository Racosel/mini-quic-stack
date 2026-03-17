#!/usr/bin/env python3

import argparse
import subprocess
import sys
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch


def build_network():
    net = Mininet(controller=Controller, switch=OVSKernelSwitch, link=TCLink)

    info("*** 添加控制器 ***\n")
    net.addController("c0")

    info("*** 添加交换机 ***\n")
    s1 = net.addSwitch("s1")

    info("*** 添加主机 (模拟 QUIC 客户端和服务端) ***\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")

    info("*** 创建带有网络特性的链路 ***\n")
    # 显式使用 TBF，避免 Mininet 默认 HTB 在 100Mbit 下反复打印 quantum warning。
    link_shape = {"bw": 100, "use_tbf": True, "latency_ms": 50}
    net.addLink(h1, s1, delay="20ms", loss=2, **link_shape)
    net.addLink(h2, s1, delay="10ms", **link_shape)

    return net


def ensure_examples_built(repo_root: Path) -> None:
    subprocess.run(["make", "quic-demo"], cwd=repo_root, check=True)


def run_auto_validation(net: Mininet, repo_root: Path) -> bool:
    h1 = net.get("h1")
    h2 = net.get("h2")
    server_cmd = (
        f"cd {repo_root} && "
        "./example/quic_server 10.0.0.2 4434 example/server_cert.pem example/server_key.pem"
    )
    client_cmd = f"cd {repo_root} && ./example/quic_client 10.0.0.2 4434"

    info("*** 构建 example 与测试证书 ***\n")
    ensure_examples_built(repo_root)

    info("*** 启动 QUIC 服务端 ***\n")
    server_proc = h2.popen(server_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.0)

    info("*** 启动 QUIC 客户端 ***\n")
    client_proc = h1.popen(client_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    try:
        client_out, _ = client_proc.communicate(timeout=25)
        server_out, _ = server_proc.communicate(timeout=25)
    except subprocess.TimeoutExpired:
        client_proc.kill()
        server_proc.kill()
        client_out, _ = client_proc.communicate()
        server_out, _ = server_proc.communicate()
        info("*** 自动验证超时 ***\n")
        sys.stdout.write(client_out.decode(errors="replace"))
        sys.stdout.write(server_out.decode(errors="replace"))
        return False

    info("*** 客户端输出 ***\n")
    sys.stdout.write(client_out.decode(errors="replace"))
    info("*** 服务端输出 ***\n")
    sys.stdout.write(server_out.decode(errors="replace"))

    return client_proc.returncode == 0 and server_proc.returncode == 0


def run_quic_test_network(auto_mode: bool) -> int:
    repo_root = Path(__file__).resolve().parent

    setLogLevel("info")
    info("*** 创建受控的 QUIC 测试网络 ***\n")
    net = build_network()

    info("*** 启动网络 ***\n")
    net.start()

    try:
        if auto_mode:
            ok = run_auto_validation(net, repo_root)
            return 0 if ok else 1

        info("*** 开启 Mininet CLI 进行交互测试 ***\n")
        CLI(net)
        return 0
    finally:
        info("*** 停止网络 ***\n")
        net.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="QUIC 测试拓扑")
    parser.add_argument("--auto", action="store_true", help="自动构建并运行 QUIC client/server 验证")
    args = parser.parse_args()
    return run_quic_test_network(args.auto)


if __name__ == "__main__":
    raise SystemExit(main())

# ==========================================
# 简易 QUIC 测试网络拓扑（Mininet）
# ==========================================
#
#   [ h1: QUIC 客户端 ]            [ h2: QUIC 服务端 ]
#     IP: 10.0.0.1                  IP: 10.0.0.2
#          |                             |
#          | (20ms 延迟, 2% 丢包)        | (10ms 延迟)
#          |                             |
#          +---------- [ s1 ] -----------+
#                    (交换机)
#
# 总计: 端到端 RTT 约 60ms，单向丢包率 2%
# ==========================================
