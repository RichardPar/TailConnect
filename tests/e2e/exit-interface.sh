#!/usr/bin/env bash
# End-to-end test of an exit node with -exit-interface: the traffic it
# forwards leaves through one chosen interface (say, another VPN's tun0),
# not its default route, and is blocked while that interface is down.
#
#   tests/e2e/exit-interface.sh  # no root needed if unprivileged user namespaces are enabled
#
# Topology (all inside a private user+mount+net namespace):
#
#   [ns a] va 10.99.0.2 ──┐                                   alpha: the client
#                         br0 10.99.0.1  ← tc-control :7740
#   [ns b] vb 10.99.0.3 ──┘                                   beta: the exit node (-exit-interface vv)
#          vi 203.0.113.1 ── [ns inet] 203.0.113.2     "the ISP": beta's default route
#          vv 10.7.7.9    ── [ns vpn]  10.7.7.1        "the VPN"
#
# Both the ISP and the VPN answer for 198.51.100.10 ("the internet"); packet
# counters on vi and vv tell which way alpha's traffic went. DNS works the
# same way: a resolver at 198.51.100.53 behind each uplink answers
# www.example.com differently (ISP 192.0.2.1, VPN 192.0.2.2), and alpha's
# own LAN resolver (10.99.0.1) answers 192.0.2.3: the answer alpha gets
# tells who resolved its name.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)

if [[ "${TC_E2E_INNER:-}" != 1 ]]; then
	WORK=$(mktemp -d "${TMPDIR:-/tmp}/tc-e2e.XXXXXX")
	echo "== building into $WORK/bin"
	(cd "$ROOT" && go build -o "$WORK/bin/" ./cmd/tc-control ./cmd/tcd ./cmd/tc)
	if [[ $(id -u) -eq 0 ]]; then
		exec env TC_E2E_INNER=1 WORK="$WORK" unshare -nm --propagation private "$0"
	fi
	exec env TC_E2E_INNER=1 WORK="$WORK" unshare -rnm --propagation private "$0"
fi

# ---- inside the namespace ----
BIN=$WORK/bin
export PATH="$BIN:$PATH"
LOG=$WORK/logs
mkdir -p "$LOG"
mount -t tmpfs tmpfs /run   # private /run for `ip netns` and sockets

pids=()
cleanup() {
	local rc=$?
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	if [[ $rc -ne 0 ]]; then
		echo "== FAILED (rc=$rc); logs:"
		for f in "$LOG"/*.log; do echo "--- $f"; tail -n 40 "$f"; done
	else
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }
wait_for() { # wait_for SECONDS DESCRIPTION CMD...
	local t=$1 what=$2; shift 2
	for ((i = 0; i < t * 10; i++)); do
		if "$@" >/dev/null 2>&1; then return 0; fi
		sleep 0.1
	done
	fail "timed out waiting for: $what"
}

INET=198.51.100.10

echo "== network"
ip link set lo up
ip link add br0 type bridge
ip addr add 10.99.0.1/24 dev br0
ip link set br0 up
for n in a b; do
	ip netns add "$n"
	ip link add "v$n" type veth peer name "v$n-br"
	ip link set "v$n-br" master br0 up
	ip link set "v$n" netns "$n"
	ip -n "$n" link set lo up
done
ip -n a addr add 10.99.0.2/24 dev va && ip -n a link set va up
ip -n b addr add 10.99.0.3/24 dev vb && ip -n b link set vb up
ip -n a route add default via 10.99.0.1
# beta's two uplinks, each with "the internet" behind it.
uplink() { # uplink NS IFACE LOCAL REMOTE
	ip netns add "$1"
	ip -n "$1" link set lo up
	ip link add "$2" type veth peer name "$2-up"
	ip link set "$2" netns b
	ip link set "$2-up" netns "$1"
	# IPv4 only: IPv6 housekeeping (MLD reports when forwarding turns on)
	# would show in the packet counters that tell where traffic went.
	ip netns exec b sysctl -qw "net.ipv6.conf.$2.disable_ipv6=1"
	ip -n b addr add "$3/24" dev "$2" && ip -n b link set "$2" up
	ip -n "$1" addr add "$4/24" dev "$2-up" && ip -n "$1" link set "$2-up" up
	ip -n "$1" addr add "$INET/32" dev lo
}
uplink inet vi 203.0.113.1 203.0.113.2
uplink vpn vv 10.7.7.9 10.7.7.1
DNS=198.51.100.53
declare -A dnspid
resolver() { # resolver NS ANSWER: a DNS server at $DNS behind an uplink
	ip -n "$1" addr add "$DNS/32" dev lo
	ip netns exec "$1" python3 -I "$ROOT/tests/e2e/fakedns.py" "$DNS" "$2" >"$LOG/dns-$1.log" 2>&1 &
	pids+=($!)
	dnspid[$1]=$!
}
resolver inet 192.0.2.1
resolver vpn 192.0.2.2
python3 -I "$ROOT/tests/e2e/fakedns.py" 10.99.0.1 192.0.2.3 >"$LOG/dns-lan.log" 2>&1 &
pids+=($!)
echo "nameserver 10.99.0.1" >"$WORK/resolv-a.conf"
# What alpha's host gets for www.example.com, asking the resolver its
# resolv.conf names (MagicDNS once tcd has set it up).
lookup() {
	ip netns exec a dig +short +time=2 +tries=1 www.example.com "@$(awk '/^nameserver/{print $2; exit}' "$WORK/resolv-a.conf")" 2>/dev/null | head -n1
}
ip -n b route add default via 203.0.113.2
ip netns exec b ping -c1 -W2 "$INET" >/dev/null || fail "beta's uplink not working"
ok "underlay: beta's default route is the ISP"

txpk() { ip netns exec b cat "/sys/class/net/$1/statistics/tx_packets"; }

echo "== control server"
export TC_CONTROL_DB=$WORK/control.db
tc-control users create alice >/dev/null
KEY=$(tc-control keys create -user alice -reusable -expiration 10m 2>/dev/null)
tc-control serve -listen 10.99.0.1:7740 -admin-listen "" -domain lan.internal >"$LOG/control.log" 2>&1 &
pids+=($!)
wait_for 5 "control listening" bash -c 'exec 3<>/dev/tcp/10.99.0.1/7740'
ok "tc-control up"

echo "== daemons"
ip netns exec a tcd -state "$WORK/state-a" -socket /run/tc-a.sock -dns file -resolv-conf "$WORK/resolv-a.conf" >"$LOG/tcd-a.log" 2>&1 &
pids+=($!)
ip netns exec b tcd -state "$WORK/state-b" -socket /run/tc-b.sock -dns off -exit-interface vv -exit-dns "$DNS" >"$LOG/tcd-b.log" 2>&1 &
pids+=($!)
tcdb=$!
for n in a b; do wait_for 5 "tcd-$n socket" test -S "/run/tc-$n.sock"; done

tca() { ip netns exec a tc --socket "/run/tc-a.sock" "$@"; }
tcb() { ip netns exec b tc --socket "/run/tc-b.sock" "$@"; }

tca up --server http://10.99.0.1:7740 --authkey "$KEY" --hostname alpha >/dev/null
tcb up --server http://10.99.0.1:7740 --authkey "$KEY" --hostname beta >/dev/null
wait_for 10 "alpha → beta" ip netns exec a ping -c1 -W1 "$(tcb ip -4)"
ok "tunnel up"

echo "== beta is an exit node through vv"
BID=$(tc-control nodes list | awk '$2=="beta"{print $1}')
tc-control nodes exit-node "$BID" on >/dev/null
wait_for 10 "beta reports it" bash -c "ip netns exec b tc --socket /run/tc-b.sock status | grep -q 'forwards internet traffic for its account, through vv'"
ok "status: $(tcb status | grep 'Exit node')"
ip -n b rule | grep -q 'iif tc0 lookup 125' || { ip -n b rule; fail "no egress rule"; }
ip -n b route show table 125 | grep -q 'unreachable default' || { ip -n b route show table 125; fail "no blocking route"; }
ok "egress rules and table in place"

wait_for 10 "MagicDNS on alpha" grep -q 100.100.100.100 "$WORK/resolv-a.conf"
[[ $(lookup) == 192.0.2.3 ]] || fail "before choosing an exit node, alpha should resolve with its LAN resolver (got $(lookup))"
ok "without an exit node, alpha's names go to its own resolver"

tca up --exit-node beta >/dev/null
wait_for 10 "alpha → internet via beta" ip netns exec a ping -c1 -W1 "$INET"
vi0=$(txpk vi) vv0=$(txpk vv)
ip netns exec a ping -c5 -i0.2 -W2 "$INET" >/dev/null || fail "exit path unstable"
vi1=$(txpk vi) vv1=$(txpk vv)
((vv1 - vv0 >= 5)) || fail "alpha's traffic didn't leave through vv (vv +$((vv1 - vv0)), vi +$((vi1 - vi0)))"
((vi1 - vi0 < 5)) || fail "alpha's traffic leaked through the default route vi (+$((vi1 - vi0)))"
ok "alpha's internet traffic leaves beta through vv (vv +$((vv1 - vv0)), vi +$((vi1 - vi0)))"
ip netns exec b ping -c1 -W1 -I 203.0.113.1 203.0.113.2 >/dev/null || fail "beta's own traffic broken"
vi0=$(txpk vi) vv0=$(txpk vv)
ip netns exec b ping -c3 -i0.2 -W1 "$INET" >/dev/null || fail "beta itself lost the internet"
vi1=$(txpk vi) vv1=$(txpk vv)
((vi1 - vi0 >= 3)) || fail "beta's own traffic moved off its default route"
ok "beta's own traffic still uses its default route (vi +$((vi1 - vi0)))"
ip netns exec a ping -c1 -W1 10.99.0.3 >/dev/null || fail "alpha lost beta's LAN address"
ok "LAN still reachable"

echo "== DNS goes through the exit node, and its VPN"
wait_for 10 "alpha's DNS via beta" bash -c "[[ \$(ip netns exec a dig +short +time=2 +tries=1 www.example.com @100.100.100.100) == 192.0.2.2 ]]"
[[ $(lookup) == 192.0.2.2 ]] || fail "alpha's lookup answered by $(lookup), want the VPN's resolver (192.0.2.2)"
ok "www.example.com resolved by the resolver behind beta's vv"
tca status | grep -q "internet traffic and DNS go through beta" || { tca status; fail "status"; }
ok "status: $(tca status | grep 'Exit node')"
ip netns exec a dig +short +time=2 +tries=1 beta.alice.lan.internal @100.100.100.100 | grep -qx "$(tcb ip -4)" || fail "MagicDNS names broken"
ok "MagicDNS names still answered by alpha itself"
ip netns exec a dig +short +time=2 +tries=1 www.example.com @"$(tcb ip -4)" -p 41653 >/dev/null 2>&1 || fail "beta's DNS port not answering alpha"
ok "beta answers DNS for alpha on its tunnel address"

echo "== kill switch: vv down"
ip -n b link set vv down
wait_for 10 "beta reports vv down" bash -c "ip netns exec b tc --socket /run/tc-b.sock status | grep -q 'vv is down'"
ok "status: $(tcb status | grep -i 'exit node')"
vi0=$(txpk vi)
ip netns exec a ping -c3 -i0.2 -W1 "$INET" >/dev/null 2>&1 && fail "internet reachable while vv is down"
vi1=$(txpk vi)
((vi1 - vi0 < 3)) || fail "traffic leaked through vi while vv was down (+$((vi1 - vi0)))"
ok "blocked, nothing leaked through vi"
got=$(lookup)
[[ -z $got ]] || fail "alpha's name resolved while vv is down: $got (192.0.2.1 = leaked through the ISP, 192.0.2.3 = alpha's own resolver)"
ok "DNS blocked too, neither the ISP's nor alpha's own resolver asked"

echo "== vv back up"
ip -n b link set vv up
ip -n b addr show dev vv | grep -q 10.7.7.9 || ip -n b addr add 10.7.7.9/24 dev vv
wait_for 15 "alpha → internet via vv again" ip netns exec a ping -c1 -W1 "$INET"
wait_for 10 "DNS via vv again" bash -c "[[ \$(ip netns exec a dig +short +time=2 +tries=1 www.example.com @100.100.100.100) == 192.0.2.2 ]]"
vv0=$(txpk vv)
ip netns exec a ping -c3 -i0.2 -W1 "$INET" >/dev/null || fail "unstable after vv came back"
(( $(txpk vv) - vv0 >= 3 )) || fail "not through vv after it came back"
ok "traffic flows through vv again by itself"

echo "== vv removed and recreated (a VPN client restarting)"
kill "${dnspid[vpn]}"; wait "${dnspid[vpn]}" 2>/dev/null || true # it would keep the namespace alive
ip netns del vpn
wait_for 10 "beta reports vv gone" bash -c "ip netns exec b tc --socket /run/tc-b.sock status | grep -q 'vv not found'"
ip netns exec a ping -c2 -i0.2 -W1 "$INET" >/dev/null 2>&1 && fail "internet reachable while vv is gone"
ok "blocked while vv is gone"
uplink vpn vv 10.7.7.9 10.7.7.1
resolver vpn 192.0.2.2
wait_for 15 "alpha → internet via the new vv" ip netns exec a ping -c1 -W1 "$INET"
ok "the new vv is used by itself"

echo "== alpha stops using the exit node"
tca up --exit-node "" >/dev/null
wait_for 10 "alpha's own resolver again" bash -c "[[ \$(ip netns exec a dig +short +time=2 +tries=1 www.example.com @100.100.100.100) == 192.0.2.3 ]]"
ok "alpha's names go to its own resolver again"
tca up --exit-node beta >/dev/null

echo "== beta stops being an exit node"
tc-control nodes exit-node "$BID" off >/dev/null
wait_for 10 "beta stops forwarding" bash -c "ip netns exec b cat /proc/sys/net/ipv4/ip_forward | grep -qx 0"
ip -n b rule | grep -q 'lookup 125' && { ip -n b rule; fail "egress rule left behind"; }
[[ -z $(ip -n b route show table 125 2>/dev/null) ]] || { ip -n b route show table 125; fail "egress table left behind"; }
ok "egress rules and table removed"

echo "== tcd stops cleanly"
tc-control nodes exit-node "$BID" on >/dev/null
wait_for 10 "egress back" bash -c "ip -n b rule | grep -q 'lookup 125'"
kill "$tcdb"; wait "$tcdb" 2>/dev/null || true
ip -n b rule | grep -q 'lookup 125' && fail "egress rule left after exit"
[[ $(ip netns exec b cat /proc/sys/net/ipv4/ip_forward) == 0 ]] || fail "beta's ip_forward left on"
ok "rules removed and forwarding restored on exit"

echo "== PASS"
