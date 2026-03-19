#!/usr/bin/env python3

import argparse
import hashlib
import os
import select
import subprocess
import sys
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch

DEFAULT_ROUNDS = 5
DEFAULT_PROFILE = "default"
TESTS_ROOT = Path("tests")
BIN_DIR = TESTS_ROOT / "bin"
CERT_DIR = TESTS_ROOT / "certs"
TRANSFER_DIR = TESTS_ROOT / "data" / "topo-transfer"
UPLOAD_FILE = TRANSFER_DIR / "client_upload.bin"
DOWNLOAD_SOURCE_FILE = TRANSFER_DIR / "server_source.bin"
SERVER_RECEIVED_FILE = TRANSFER_DIR / "server_received.bin"
CLIENT_DOWNLOADED_FILE = TRANSFER_DIR / "client_downloaded.bin"
SERVER_BIN = BIN_DIR / "quic_server"
CLIENT_BIN = BIN_DIR / "quic_client"
SERVER_CERT = CERT_DIR / "server_cert.pem"
SERVER_KEY = CERT_DIR / "server_key.pem"
SERVER_READY_MARKER = "server listening on "
SERVER_READY_TIMEOUT_S = 10.0
STAGE5_PREFERRED_PORT = 4445
ANSI_RESET = "\033[0m"
ANSI_ERROR_BG = "\033[41;97m"
ANSI_DONE_BG = "\033[42;30m"

NETWORK_PROFILES = {
    "default": {
        "description": "阶段 2/3 默认文件传输验证",
        "bw_mbit": 100,
        "client_delay_ms": 20,
        "server_delay_ms": 10,
        "client_loss_pct": 2.0,
        "server_loss_pct": 0.0,
        "upload_size": 32768,
        "download_size": 24576,
    },
    "clean-bdp": {
        "description": "阶段 4 clean BDP 验证：无丢包的大 bulk 传输",
        "bw_mbit": 100,
        "client_delay_ms": 20,
        "server_delay_ms": 10,
        "client_loss_pct": 0.0,
        "server_loss_pct": 0.0,
        "upload_size": 131072,
        "download_size": 98304,
    },
    "lossy-recovery": {
        "description": "阶段 4 lossy recovery 验证：有丢包的大 bulk 传输",
        "bw_mbit": 100,
        "client_delay_ms": 20,
        "server_delay_ms": 10,
        "client_loss_pct": 2.0,
        "server_loss_pct": 0.0,
        "upload_size": 131072,
        "download_size": 98304,
    },
    "app-limited": {
        "description": "小文件应用受限验证",
        "bw_mbit": 100,
        "client_delay_ms": 20,
        "server_delay_ms": 10,
        "client_loss_pct": 0.0,
        "server_loss_pct": 0.0,
        "upload_size": 4096,
        "download_size": 4096,
    },
    "preferred-address": {
        "description": "阶段 5 preferred-address 迁移后继续文件传输",
        "bw_mbit": 100,
        "client_delay_ms": 20,
        "server_delay_ms": 10,
        "client_loss_pct": 0.0,
        "server_loss_pct": 0.0,
        "upload_size": 65536,
        "download_size": 49152,
    },
}


def supports_ansi() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "dumb") != "dumb"


def status_label(name: str, background: str) -> str:
    if not supports_ansi():
        return name
    return f"{background} {name} {ANSI_RESET}"


def info_error(message: str) -> None:
    info(f"*** {status_label('ERROR', ANSI_ERROR_BG)} {message} ***\n")


def info_done(message: str) -> None:
    info(f"*** {status_label('DONE', ANSI_DONE_BG)} {message} ***\n")


def resolve_profile(profile_name: str, bw: float | None, delay: int | None, loss: float | None) -> dict:
    if profile_name not in NETWORK_PROFILES:
        raise ValueError(f"unknown profile: {profile_name}")

    profile = dict(NETWORK_PROFILES[profile_name])
    if bw is not None:
        profile["bw_mbit"] = bw
    if delay is not None:
        profile["client_delay_ms"] = delay
        profile["server_delay_ms"] = delay
    if loss is not None:
        profile["client_loss_pct"] = loss
        profile["server_loss_pct"] = loss
    return profile


def build_network(profile: dict):
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
    link_shape = {"bw": profile["bw_mbit"], "use_tbf": True, "latency_ms": 50}
    net.addLink(h1, s1, delay=f"{profile['client_delay_ms']}ms", loss=profile["client_loss_pct"], **link_shape)
    net.addLink(h2, s1, delay=f"{profile['server_delay_ms']}ms", loss=profile["server_loss_pct"], **link_shape)

    return net


def ensure_examples_built(repo_root: Path) -> None:
    subprocess.run(["make", "quic-demo"], cwd=repo_root, check=True)


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes(((index * 131 + seed) % 256 for index in range(size)))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_file_transfer_case(repo_root: Path, profile: dict) -> dict:
    transfer_dir = repo_root / TRANSFER_DIR
    upload_path = repo_root / UPLOAD_FILE
    download_source_path = repo_root / DOWNLOAD_SOURCE_FILE
    server_received_path = repo_root / SERVER_RECEIVED_FILE
    client_downloaded_path = repo_root / CLIENT_DOWNLOADED_FILE

    transfer_dir.mkdir(parents=True, exist_ok=True)
    for reset_path in (upload_path, download_source_path, server_received_path, client_downloaded_path):
        if reset_path.exists():
            reset_path.unlink()
    upload_path.write_bytes(deterministic_bytes(profile["upload_size"], 17))
    download_source_path.write_bytes(deterministic_bytes(profile["download_size"], 83))

    return {
        "upload_path": upload_path,
        "download_source_path": download_source_path,
        "server_received_path": server_received_path,
        "client_downloaded_path": client_downloaded_path,
        "upload_size": upload_path.stat().st_size,
        "download_size": download_source_path.stat().st_size,
        "upload_sha256": sha256_file(upload_path),
        "download_sha256": sha256_file(download_source_path),
    }


def prime_connectivity(h1, h2) -> None:
    # 预热 ARP/邻居项，减少首个 QUIC Initial 叠加地址解析的不确定性。
    h1.cmd("ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1 || true")
    h2.cmd("ping -c 1 -W 1 10.0.0.1 >/dev/null 2>&1 || true")


def restore_path_ownership(path: Path, uid: int, gid: int) -> None:
    if not path.exists():
        return
    os.chown(path, uid, gid)
    if path.is_dir():
        for child in path.iterdir():
            restore_path_ownership(child, uid, gid)


def restore_test_artifact_ownership(repo_root: Path) -> None:
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")

    if os.geteuid() != 0 or sudo_uid is None or sudo_gid is None:
        return

    uid = int(sudo_uid)
    gid = int(sudo_gid)
    for owned_path in (repo_root / BIN_DIR, repo_root / CERT_DIR, repo_root / (TESTS_ROOT / "data")):
        if owned_path.exists():
            restore_path_ownership(owned_path, uid, gid)


def wait_for_server_ready(server_proc: subprocess.Popen, timeout_s: float) -> tuple[bool, str]:
    collected: list[str] = []
    deadline = time.monotonic() + timeout_s

    if server_proc.stdout is None:
        return False, ""

    while time.monotonic() < deadline:
        if server_proc.poll() is not None:
            tail = server_proc.stdout.read() or ""
            if tail:
                collected.append(tail)
            return False, "".join(collected)

        ready, _, _ = select.select([server_proc.stdout], [], [], 0.2)
        if not ready:
            continue

        line = server_proc.stdout.readline()
        if not line:
            continue
        collected.append(line)
        if SERVER_READY_MARKER in line:
            return True, "".join(collected)

    return False, "".join(collected)


def verify_file_transfer_case(case: dict) -> bool:
    upload_path = case["upload_path"]
    download_source_path = case["download_source_path"]
    server_received_path = case["server_received_path"]
    client_downloaded_path = case["client_downloaded_path"]

    if not server_received_path.exists():
        info_error("文件校验失败：服务端未生成接收文件")
        return False
    if not client_downloaded_path.exists():
        info_error("文件校验失败：客户端未生成下载文件")
        return False

    upload_ok = upload_path.read_bytes() == server_received_path.read_bytes()
    download_ok = download_source_path.read_bytes() == client_downloaded_path.read_bytes()

    info("*** 文件传输校验 ***\n")
    info(
        f"客户端上传: size={case['upload_size']} sha256={case['upload_sha256']}\n"
    )
    info(
        f"服务端接收: size={server_received_path.stat().st_size} sha256={sha256_file(server_received_path)}\n"
    )
    info(
        f"服务端源文件: size={case['download_size']} sha256={case['download_sha256']}\n"
    )
    info(
        f"客户端下载: size={client_downloaded_path.stat().st_size} sha256={sha256_file(client_downloaded_path)}\n"
    )

    if upload_ok and download_ok:
        info_done("文件传输校验通过")
        return True

    info_error("文件传输校验失败")
    return False


def print_manual_instructions(repo_root: Path, auto_file_mode: bool, rounds: int, profile: dict, profile_name: str) -> None:
    info("*** 当前进程无 root 权限，无法启动 Mininet ***\n")
    print("请在具备 sudo 权限的终端手动执行以下命令：")
    if auto_file_mode:
        print(f"  sudo python3 topo.py --auto-file --profile {profile_name} --rounds {rounds}")
        try:
            case = prepare_file_transfer_case(repo_root, profile)
            print("已预生成文件传输测试数据：")
            print(f"  客户端上传源文件: {case['upload_path']}")
            print(f"  服务端发送源文件: {case['download_source_path']}")
            print(f"  预期服务端接收文件: {case['server_received_path']}")
            print(f"  预期客户端下载文件: {case['client_downloaded_path']}")
            print(f"  上传文件 sha256: {case['upload_sha256']}")
            print(f"  下载文件 sha256: {case['download_sha256']}")
        except PermissionError as exc:
            print("测试数据目录当前不可写，通常是之前用 sudo 运行后遗留的 root 权限。")
            print(f"  触发路径: {exc.filename}")
            print("可先执行以下命令恢复目录所有权，再重试无 root 预生成：")
            print(f"  sudo chown -R $USER:$USER {repo_root / (TESTS_ROOT / 'data')}")
    else:
        print(f"  sudo python3 topo.py --auto --profile {profile_name} --rounds {rounds}")

def run_single_auto_validation(net: Mininet,
                               repo_root: Path,
                               auto_file_mode: bool,
                               round_index: int,
                               rounds: int,
                               profile: dict,
                               profile_name: str) -> bool:
    h1 = net.get("h1")
    h2 = net.get("h2")
    case = prepare_file_transfer_case(repo_root, profile) if auto_file_mode else None

    info(f"*** 第 {round_index}/{rounds} 轮自动验证 ({profile_name}: {profile['description']}) ***\n")
    if auto_file_mode:
        extra_args = f" {STAGE5_PREFERRED_PORT}" if profile_name == "preferred-address" else ""
        server_cmd = (
            f"cd {repo_root} && "
            f"./{SERVER_BIN} 10.0.0.2 4434 {SERVER_CERT} {SERVER_KEY} "
            f"{SERVER_RECEIVED_FILE} {DOWNLOAD_SOURCE_FILE}{extra_args}"
        )
        client_cmd = (
            f"cd {repo_root} && "
            f"./{CLIENT_BIN} 10.0.0.2 4434 {UPLOAD_FILE} {CLIENT_DOWNLOADED_FILE}{extra_args}"
        )
    else:
        server_cmd = (
            f"cd {repo_root} && "
            f"./{SERVER_BIN} 10.0.0.2 4434 {SERVER_CERT} {SERVER_KEY}"
        )
        client_cmd = f"cd {repo_root} && ./{CLIENT_BIN} 10.0.0.2 4434"

    if auto_file_mode:
        info("*** 已准备文件传输测试数据 ***\n")
        info(
            f"上传文件: {UPLOAD_FILE} ({case['upload_size']} bytes, sha256={case['upload_sha256']})\n"
        )
        info(
            f"下载文件: {DOWNLOAD_SOURCE_FILE} ({case['download_size']} bytes, sha256={case['download_sha256']})\n"
        )

    prime_connectivity(h1, h2)

    info("*** 启动 QUIC 服务端 ***\n")
    server_proc = h2.popen(
        server_cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    server_ready, server_prefix = wait_for_server_ready(server_proc, SERVER_READY_TIMEOUT_S)
    if not server_ready:
        info_error("服务端就绪等待失败")
        sys.stdout.write(server_prefix)
        if server_proc.poll() is None:
            server_proc.kill()
        server_tail, _ = server_proc.communicate()
        if server_tail:
            sys.stdout.write(server_tail)
        return False
    time.sleep(0.2)

    info("*** 启动 QUIC 客户端 ***\n")
    client_proc = h1.popen(
        client_cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        client_out, _ = client_proc.communicate(timeout=40 if auto_file_mode else 25)
        server_out, _ = server_proc.communicate(timeout=40 if auto_file_mode else 25)
    except subprocess.TimeoutExpired:
        client_proc.kill()
        server_proc.kill()
        client_out, _ = client_proc.communicate()
        server_out, _ = server_proc.communicate()
        info_error("自动验证超时")
        sys.stdout.write(client_out)
        sys.stdout.write(server_prefix + server_out)
        return False

    info("*** 客户端输出 ***\n")
    sys.stdout.write(client_out)
    info("*** 服务端输出 ***\n")
    sys.stdout.write(server_prefix + server_out)

    if client_proc.returncode != 0 or server_proc.returncode != 0:
        info_error(f"第 {round_index}/{rounds} 轮自动验证失败")
        return False
    if auto_file_mode:
        ok = verify_file_transfer_case(case)
        if ok:
            info_done(f"第 {round_index}/{rounds} 轮自动验证完成")
        return ok

    info_done(f"第 {round_index}/{rounds} 轮自动验证完成")
    return True


def run_auto_validation(net: Mininet,
                        repo_root: Path,
                        auto_file_mode: bool,
                        rounds: int,
                        profile: dict,
                        profile_name: str) -> bool:
    round_index = 1

    info("*** 构建 example 与测试证书 ***\n")
    ensure_examples_built(repo_root)
    while round_index <= rounds:
        if not run_single_auto_validation(net, repo_root, auto_file_mode, round_index, rounds, profile, profile_name):
            return False
        round_index += 1
    info_done("全部自动验证完成")
    return True


def run_quic_test_network(auto_mode: bool,
                          auto_file_mode: bool,
                          rounds: int,
                          profile_name: str,
                          bw: float | None,
                          delay: int | None,
                          loss: float | None) -> int:
    repo_root = Path(__file__).resolve().parent
    profile = resolve_profile(profile_name, bw, delay, loss)

    if os.geteuid() != 0:
        print_manual_instructions(repo_root, auto_file_mode, rounds, profile, profile_name)
        return 0

    setLogLevel("info")
    info("*** 创建受控的 QUIC 测试网络 ***\n")
    info(f"*** 采用网络 profile: {profile_name} ({profile['description']}) ***\n")
    net = build_network(profile)

    info("*** 启动网络 ***\n")
    net.start()

    try:
        if auto_mode or auto_file_mode:
            ok = run_auto_validation(net, repo_root, auto_file_mode, rounds, profile, profile_name)
            if not ok:
                info_error("自动验证失败")
            return 0 if ok else 1

        info("*** 开启 Mininet CLI 进行交互测试 ***\n")
        CLI(net)
        return 0
    finally:
        restore_test_artifact_ownership(repo_root)
        info("*** 停止网络 ***\n")
        net.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="QUIC 测试拓扑")
    parser.add_argument("--auto", action="store_true", help="自动构建并运行 QUIC client/server 验证")
    parser.add_argument("--auto-file", action="store_true", help="自动构建并运行包含文件传输的 QUIC client/server 验证")
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, help="自动验证轮数，默认 5")
    parser.add_argument("--profile",
                        choices=sorted(NETWORK_PROFILES.keys()),
                        default=DEFAULT_PROFILE,
                        help="链路与流量 profile，默认 default")
    parser.add_argument("--bw", type=float, default=None, help="覆盖 profile 的链路带宽（Mbit/s）")
    parser.add_argument("--delay", type=int, default=None, help="覆盖 profile 的双向链路时延（ms）")
    parser.add_argument("--loss", type=float, default=None, help="覆盖 profile 的双向链路丢包率（百分比）")
    args = parser.parse_args()
    return run_quic_test_network(args.auto, args.auto_file, args.rounds, args.profile, args.bw, args.delay, args.loss)


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
