#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# End-to-end eBPF tunnel test suite
#   The script tests BPF network tunnel implementation.
#
# Topology:
# ---------
#     root namespace   |     at_ns0 namespace
#                      |
#      -----------     |     -----------
#      | tnl dev |     |     | tnl dev |  (overlay network)
#      -----------     |     -----------
#      metadata-mode   |     native-mode
#       with bpf       |     10.1.1.100
#        10.1.1.200    |
#                      |
#      ----------      |     ----------
#      |  veth1  | --------- |  veth0  |  (underlay network)
#      ----------    peer    ----------
#      172.16.1.200          172.16.1.100
#
# Device Configuration
# --------------------
# Root namespace with metadata-mode tunnel + BPF
# Device names and addresses:
# 	veth1 IP: 172.16.1.200, IPv6: 00::22 (underlay)
# 	tunnel dev <type>11, ex: gre11, IPv4: 10.1.1.200, IPv6: 1::22 (overlay)
#
# Namespace at_ns0 with native tunnel
# Device names and addresses:
# 	veth0 IPv4: 172.16.1.100, IPv6: 00::11 (underlay)
# 	tunnel dev <type>00, ex: gre00, IPv4: 10.1.1.100, IPv6: 1::11 (overlay)
#
#
# End-to-end ping packet flow
# ---------------------------
# Most of the tests start by namespace creation, device configuration,
# then ping the underlay and overlay network.  When doing 'ping 10.1.1.100'
# from root namespace, the following operations happen:
# 1) Route lookup shows 10.1.1.100/24 belongs to tnl dev, fwd to tnl dev.
# 2) Tnl device's egress BPF program is triggered and set the tunnel metadata,
#    with remote_ip=172.16.1.100 and others.
# 3) Outer tunnel header is prepended and route the packet to veth1's egress
# 4) veth0's ingress queue receive the tunneled packet at namespace at_ns0
# 5) Tunnel protocol handler, ex: vxlan_rcv, decap the packet
# 6) Forward the packet to the overlay tnl dev



# 精简自 test_tunnel.sh， 优化拓扑图展示、添加 prompt 函数用于暂存环境调试
# 容器内的 tnl 设备采用原生模式，创建时指明 remote 和 local
# root namespace 内的 tnl 设备创建时声明 external，由外部控制，即 bpf 程序附加到 tnl 设备上
# 5.19 将 vxlan 测试移出到用户态 libbpf c 文件中。 Ref: https://github.com/torvalds/linux/commit/1ee7efd40abf3ab01e67ff4be15d4385d5fa52c1

PING_ARG="-c 3 -w 10 -q"
ret=0
GREEN='\033[0;92m'
RED='\033[0;31m'
NC='\033[0m' # No Color

config_device()
{
	ip netns add at_ns0
	ip link add veth0 type veth peer name veth1
	ip link set veth0 netns at_ns0
	ip netns exec at_ns0 ip addr add 172.16.1.100/24 dev veth0
	ip netns exec at_ns0 ip link set dev veth0 up
	ip link set dev veth1 up mtu 1500
	ip addr add dev veth1 172.16.1.200/24
}

add_ipip_tunnel()
{
	# at_ns0 namespace
	ip netns exec at_ns0 \
		ip link add dev $DEV_NS type $TYPE \
		local 172.16.1.100 remote 172.16.1.200
	ip netns exec at_ns0 ip link set dev $DEV_NS up
	ip netns exec at_ns0 ip addr add dev $DEV_NS 10.1.1.100/24

	# root namespace
	ip link add dev $DEV type $TYPE external
	ip link set dev $DEV up
	ip addr add dev $DEV 10.1.1.200/24
}

test_ipip()
{
	TYPE=ipip
	DEV_NS=ipip00
	DEV=ipip11
	ret=0

	check $TYPE
	config_device
	add_ipip_tunnel
	ip link set dev veth1 mtu 1500
	attach_bpf $DEV ipip_set_tunnel ipip_get_tunnel
	ping $PING_ARG 10.1.1.100
	check_err $?
	ip netns exec at_ns0 ping $PING_ARG 10.1.1.200
	check_err $?
	prompt
	cleanup

	if [ $ret -ne 0 ]; then
                echo -e ${RED}"FAIL: $TYPE"${NC}
                return 1
        fi
        echo -e ${GREEN}"PASS: $TYPE"${NC}
}

attach_bpf()
{
	DEV=$1
	SET=$2
	GET=$3
	tc qdisc add dev $DEV clsact
	tc filter add dev $DEV egress bpf da obj test_tunnel_kern.o sec $SET
	tc filter add dev $DEV ingress bpf da obj test_tunnel_kern.o sec $GET
}

cleanup()
{
	ip netns delete at_ns0 2> /dev/null
	ip link del veth1 2> /dev/null
	ip link del ipip11 2> /dev/null
}

cleanup_exit()
{
	echo "CATCH SIGKILL or SIGINT, cleanup and exit"
	cleanup
	exit 0
}

check()
{
	ip link help 2>&1 | grep -q "\s$1\s"
	if [ $? -ne 0 ];then
		echo "SKIP $1: iproute2 not support"
	cleanup
	return 1
	fi
}

check_err()
{
	if [ $ret -eq 0 ]; then
		ret=$1
	fi
}

prompt()
{
	echo "press any key to start..."
	read
}

bpf_tunnel_test()
{
	local errors=0

	echo "Testing IPIP tunnel..."
	test_ipip
	errors=$(( $errors + $? ))

	return $errors
}

trap cleanup 0 3 6
trap cleanup_exit 2 9

cleanup
bpf_tunnel_test

if [ $? -ne 0 ]; then
	echo -e "$(basename $0): ${RED}FAIL${NC}"
	exit 1
fi
echo -e "$(basename $0): ${GREEN}PASS${NC}"
exit 0
