clean:
# 清理 Mininet 拓扑残留
	sudo mn -c > /dev/null 2>&1
	
	@echo "--- Killing zombie controllers ---"
# 强行终止占用 6653 端口的进程（如果存在）
	-sudo fuser -k 6653/tcp > /dev/null 2>&1
	
	@echo "--- Resetting Firewall Rules ---"
# 清理 iptables 中关于 12345 端口的丢弃规则
# 使用 -D 命令。为了防止规则不存在时报错，末尾加了 || true
	-sudo iptables -D OUTPUT -p tcp --sport 12345 --tcp-flags RST RST -j DROP > /dev/null 2>&1 || true

net:
	sudo python3 topo.py