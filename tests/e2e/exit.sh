#!/usr/bin/env bash
# End-to-end test of exit nodes, using real TUN devices, policy routing,
# nftables NAT and ping, inside network namespaces.
#
#   tests/e2e/exit.sh            # no root needed if unprivileged user namespaces are enabled
#   TC_EXIT_IPTABLES=1 tests/e2e/exit.sh   # the exit node does NAT with iptables, as where nftables doesn't work
#
# Topology (all inside a private user+mount+net namespace):
#
#   [ns a] va 10.99.0.2 ──┐                                   alpha: the client
#                         br0 10.99.0.1  ← tc-control :7740
#   [ns b] vb 10.99.0.3 ──┘                                   beta: the exit node
#          vi 203.0.113.1 ── [ns inet] 203.0.113.2, and 198.51.100.10 ("the internet")
#
# alpha can't reach 198.51.100.10 by itself, and the internet has no route
# back to the tunnel's addresses: a reply means beta forwarded and NATed it.
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
# alpha's own default route leads nowhere useful: the LAN has no internet.
ip -n a route add default via 10.99.0.1
# beta's internet uplink.
ip netns add inet
ip -n inet link set lo up
ip link add vi type veth peer name vi-inet
ip link set vi netns b
ip link set vi-inet netns inet
ip -n b addr add 203.0.113.1/24 dev vi && ip -n b link set vi up
ip -n inet addr add 203.0.113.2/24 dev vi-inet && ip -n inet link set vi-inet up
ip -n inet addr add "$INET/32" dev lo
ip -n b route add default via 203.0.113.2
ip netns exec b ping -c1 -W2 "$INET" >/dev/null || fail "beta's uplink not working"
ip netns exec a ping -c1 -W1 "$INET" >/dev/null 2>&1 && fail "alpha reaches the internet by itself"
ok "underlay: beta has internet, alpha doesn't"

echo "== control server"
export TC_CONTROL_DB=$WORK/control.db
tc-control users create alice >/dev/null
KEY=$(tc-control keys create -user alice -reusable -expiration 10m 2>/dev/null)
tc-control serve -listen 10.99.0.1:7740 -admin-listen "" -domain lan.internal >"$LOG/control.log" 2>&1 &
pids+=($!)
wait_for 5 "control listening" bash -c 'exec 3<>/dev/tcp/10.99.0.1/7740'
ok "tc-control up"

echo "== daemons"
for n in a b; do
	ip netns exec "$n" tcd -state "$WORK/state-$n" -socket "/run/tc-$n.sock" -dns off >"$LOG/tcd-$n.log" 2>&1 &
	pids+=($!)
done
for n in a b; do wait_for 5 "tcd-$n socket" test -S "/run/tc-$n.sock"; done

tca() { ip netns exec a tc --socket "/run/tc-a.sock" "$@"; }
tcb() { ip netns exec b tc --socket "/run/tc-b.sock" "$@"; }

tca up --server http://10.99.0.1:7740 --authkey "$KEY" --hostname alpha >/dev/null
tcb up --server http://10.99.0.1:7740 --authkey "$KEY" --hostname beta >/dev/null
IPB=$(tcb ip -4)
wait_for 10 "alpha → beta" ip netns exec a ping -c1 -W1 "$IPB"
ok "tunnel up"

echo "== exit node off by default"
[[ $(ip netns exec b cat /proc/sys/net/ipv4/ip_forward) == 0 ]] || fail "beta forwards before being an exit node"
out=$(tca up --exit-node beta 2>&1) && fail "using a machine that isn't an exit node was accepted: $out"
grep -q "not an exit node" <<<"$out" || fail "unexpected error: $out"
ok "refused: $out"

echo "== beta becomes an exit node"
BID=$(tc-control nodes list | awk '$2=="beta"{print $1}')
tc-control nodes exit-node "$BID" on >/dev/null
wait_for 10 "beta forwards" bash -c "ip netns exec b cat /proc/sys/net/ipv4/ip_forward | grep -qx 1"
wait_for 5 "beta reports it" bash -c "ip netns exec b tc --socket /run/tc-b.sock status | grep -q 'this machine forwards'"
ok "beta forwards (ip_forward=1)"
if [[ ${TC_EXIT_IPTABLES:-} == 1 ]]; then
	ip netns exec b iptables -w -t nat -S POSTROUTING | grep -q tailconnect-exit || fail "no iptables NAT rule"
	ip netns exec b iptables -w -S FORWARD | grep -q -- "-i tc0 -o tc0 .*-j DROP" || fail "no iptables tc0 → tc0 drop"
	ok "NAT and forwarding through iptables"
fi
wait_for 10 "alpha sees beta as an exit node" bash -c "ip netns exec a tc --socket /run/tc-a.sock status | grep -q 'beta.*exit node'"
ok "alpha sees beta as an exit node"
ip netns exec a ping -c1 -W1 "$INET" >/dev/null 2>&1 && fail "alpha uses the exit node without choosing it"
ok "alpha still goes direct until it chooses"

echo "== alpha uses beta"
tca up --exit-node beta
ip -n a rule | grep -q "lookup 124" || fail "no policy rule"
wait_for 10 "alpha → internet via beta" ip netns exec a ping -c1 -W1 "$INET"
ip netns exec a ping -c5 -i0.2 -W2 "$INET" >/dev/null || fail "exit path unstable"
ok "alpha reaches the internet through beta"
ip netns exec a ping -c1 -W1 10.99.0.1 >/dev/null || fail "alpha lost its LAN"
ok "LAN still direct"
tca status | grep -q "Exit node: internet traffic and DNS go through beta" || { tca status; fail "status"; }
tca status | grep -q "exit node (in use)" || { tca status; fail "peer line"; }
ok "status shows the exit node in use"
# The tunnel itself (WireGuard, control) must not loop into the tunnel.
sleep 3
tca status --json | grep -q '"State": "Running"' || fail "alpha lost control"
tca status | grep -q "direct 10.99.0.3" || { tca status; fail "WireGuard not on the direct path"; }
ok "WireGuard and control bypass the exit route"

echo "== beta stops being an exit node"
tc-control nodes exit-node "$BID" off >/dev/null
wait_for 10 "beta stops forwarding" bash -c "ip netns exec b cat /proc/sys/net/ipv4/ip_forward | grep -qx 0"
ok "beta restored ip_forward=0"
if [[ ${TC_EXIT_IPTABLES:-} == 1 ]]; then
	ip netns exec b iptables -w -t nat -S | grep -q tailconnect-exit && fail "iptables NAT rule left behind"
	ip netns exec b iptables -w -S | grep -q tailconnect-exit && fail "iptables forward rule left behind"
	ok "iptables rules removed"
fi
wait_for 10 "alpha falls back" bash -c "ip netns exec a tc --socket /run/tc-a.sock status | grep -q 'not in use'"
ip netns exec a ping -c1 -W1 "$INET" >/dev/null 2>&1 && fail "internet still reachable through beta"
ip -n a rule | grep -q "lookup 124" && fail "policy rule left behind"
ok "alpha warned and went direct: $(tca status | grep 'exit node')"

echo "== back on, then alpha turns it off"
tc-control nodes exit-node "$BID" on >/dev/null
wait_for 15 "alpha uses beta again" ip netns exec a ping -c1 -W1 "$INET"
ok "alpha uses beta again by itself"
tca up --exit-node "" >/dev/null
ip netns exec a ping -c1 -W1 "$INET" >/dev/null 2>&1 && fail "still routed after --exit-node \"\""
ip -n a rule | grep -q "lookup 124" && fail "policy rule left behind"
tca status | grep -qi "exit node:" && fail "status still mentions an exit node"
ok "alpha off the exit node"

echo "== tcd stops cleanly"
tca up --exit-node beta >/dev/null
wait_for 10 "alpha → internet" ip netns exec a ping -c1 -W1 "$INET"
kill "${pids[1]}" "${pids[2]}"; wait "${pids[1]}" "${pids[2]}" 2>/dev/null || true
ip -n a rule | grep -q "lookup 124" && fail "alpha's policy rule left after exit"
[[ $(ip netns exec b cat /proc/sys/net/ipv4/ip_forward) == 0 ]] || fail "beta's ip_forward left on"
ok "rules removed and forwarding restored on exit"

echo "== PASS"
