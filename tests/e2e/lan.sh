#!/usr/bin/env bash
# End-to-end test of milestone 2 on a simulated LAN, using real TUN devices,
# netlink routes and ping, inside network namespaces.
#
#   tests/e2e/lan.sh            # no root needed if unprivileged user namespaces are enabled
#
# Topology (all inside a private user+mount+net namespace):
#
#   [ns a] va 10.99.0.2 ──┐
#                         br0 10.99.0.1  ← tc-control :8080
#   [ns b] vb 10.99.0.3 ──┘
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
ip netns exec a ping -c1 -W2 10.99.0.3 >/dev/null || fail "underlay LAN not working"
ok "underlay LAN"

echo "== control server"
export TC_CONTROL_DB=$WORK/control.db
tc-control users create alice >/dev/null
KEY=$(tc-control keys create -user alice -reusable -expiration 10m 2>/dev/null)
tc-control serve -listen 10.99.0.1:8080 -admin-listen "" -domain lan.internal >"$LOG/control.log" 2>&1 &
pids+=($!)
wait_for 5 "control listening" bash -c 'exec 3<>/dev/tcp/10.99.0.1/8080'
ok "tc-control up"

echo "== daemons"
for n in a b; do
	ip netns exec "$n" tcd -state "$WORK/state-$n" -socket "/run/tc-$n.sock" >"$LOG/tcd-$n.log" 2>&1 &
	pids+=($!)
done
for n in a b; do wait_for 5 "tcd-$n socket" test -S "/run/tc-$n.sock"; done

tca() { ip netns exec a tc --socket "/run/tc-a.sock" "$@"; }
tcb() { ip netns exec b tc --socket "/run/tc-b.sock" "$@"; }

tca up --server http://10.99.0.1:8080 --authkey "$KEY" --hostname alpha
tcb up --server http://10.99.0.1:8080 --authkey "$KEY" --hostname beta
IPA=$(tca ip -4); IPB=$(tcb ip -4)
IPA6=$(tca ip -6); IPB6=$(tcb ip -6)
ok "alpha=$IPA/$IPA6 beta=$IPB/$IPB6"
[[ $(tca ip -4 beta) == "$IPB" ]] || fail "tc ip beta"

wait_for 10 "alpha has route to beta" bash -c "ip -n a route show dev tc0 | grep -q '^$IPB '"
ok "routes installed"

echo "== tunnel traffic"
ip netns exec a ping -c3 -i0.2 -W2 "$IPB" >/dev/null || fail "alpha → beta IPv4 ping"
ok "alpha → beta (IPv4)"
ip netns exec b ping -c3 -i0.2 -W2 "$IPA" >/dev/null || fail "beta → alpha IPv4 ping"
ok "beta → alpha (IPv4)"
if ip netns exec a ping -6 -c3 -i0.2 -W2 "$IPB6" >/dev/null 2>&1; then
	ok "alpha → beta (IPv6)"
else
	echo "  skip: IPv6 ping (IPv6 unavailable?)"
fi
tca status
tca status --json | grep -q '"Active": true' || fail "status does not show an active peer"
ok "status shows active peer"

echo "== restart resumes session"
kill "${pids[1]}"; wait "${pids[1]}" 2>/dev/null || true
ip netns exec a tcd -state "$WORK/state-a" -socket "/run/tc-a.sock" >>"$LOG/tcd-a.log" 2>&1 &
pids[1]=$!
wait_for 10 "alpha running after restart" bash -c "ip netns exec a tc --socket /run/tc-a.sock status --json | grep -q '\"State\": \"Running\"'"
wait_for 10 "alpha → beta after restart" ip netns exec a ping -c1 -W1 "$IPB"
ok "tcd restart resumed without re-auth"

echo "== down / up"
tca down >/dev/null
ip netns exec a ping -c1 -W1 "$IPB" >/dev/null 2>&1 && fail "ping works while down"
tca up >/dev/null
wait_for 10 "alpha → beta after up" ip netns exec a ping -c1 -W1 "$IPB"
ok "down/up"

echo "== relay failover (direct path cut)"
ip -n a route add blackhole 10.99.0.3/32
ip -n b route add blackhole 10.99.0.2/32
ip netns exec a ping -c1 -W1 10.99.0.3 >/dev/null 2>&1 && fail "blackhole not effective"
# The trusted direct path expires after 15s without direct packets; then
# traffic moves to the relay embedded in tc-control.
t0=$(date +%s)
wait_for 30 "alpha → beta via relay" ip netns exec a ping -c1 -W1 "$IPB"
ok "failed over to relay after $(( $(date +%s) - t0 ))s"
ip netns exec a ping -c5 -i0.2 -W2 "$IPB" >/dev/null || fail "relay path unstable"
tca status | grep -q "relay 1" || { tca status; fail "status does not show relay path"; }
ok "status shows relay path"
ip -n a route del blackhole 10.99.0.3/32
ip -n b route del blackhole 10.99.0.2/32
wait_for 20 "back to direct" bash -c "ip netns exec a ping -c1 -W1 $IPB >/dev/null; ip netns exec a tc --socket /run/tc-a.sock status | grep -q 'direct 10.99.0.3'"
ok "returned to direct path"

echo "== admin removes beta"
BID=$(tc-control nodes list | awk '$2=="beta"{print $1}')
tc-control nodes delete "$BID" >/dev/null
wait_for 10 "alpha drops route to beta" bash -c "! ip -n a route show dev tc0 | grep -q '^$IPB '"
ok "alpha removed beta's route"
wait_for 10 "beta needs login" bash -c "ip netns exec b tc --socket /run/tc-b.sock status | grep -q 'Logged out'"
ok "beta told to log in again"

echo "== logout"
tca logout >/dev/null
[[ -z $(tc-control nodes list | awk 'NR>1') ]] || fail "nodes remain after logout"
ok "alpha logged out"

echo "== PASS"
