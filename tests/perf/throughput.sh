#!/usr/bin/env bash
# Throughput and latency through TailConnect with real kernel TUN devices,
# inside network namespaces (no root needed with unprivileged user
# namespaces). Compares the bare network ("underlay") with the tunnel on a
# direct path and through the relay.
#
#   tests/perf/throughput.sh                 # 5s per throughput test
#   DURATION=10s RTTS=5000 tests/perf/throughput.sh
#
# Topology: two machines on a bridged LAN, tc-control on the bridge.
#
#   [ns a] 10.99.0.2 ──┐
#                      br0 10.99.0.1  ← tc-control :7740 (relay)
#   [ns b] 10.99.0.3 ──┘
#
# Optional budgets (fail if slower), e.g. in CI:
#   MIN_DIRECT_MBPS=50 MIN_RELAY_MBPS=20 tests/perf/throughput.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DURATION=${DURATION:-5s}
RTTS=${RTTS:-2000}

if [[ "${TC_PERF_INNER:-}" != 1 ]]; then
	WORK=$(mktemp -d "${TMPDIR:-/tmp}/tc-perf.XXXXXX")
	echo "== building into $WORK/bin"
	(cd "$ROOT" && go build -o "$WORK/bin/" ./cmd/tc-control ./cmd/tcd ./cmd/tc ./tests/perf/tput)
	if [[ $(id -u) -eq 0 ]]; then
		exec env TC_PERF_INNER=1 WORK="$WORK" DURATION="$DURATION" RTTS="$RTTS" unshare -nm --propagation private "$0"
	fi
	exec env TC_PERF_INNER=1 WORK="$WORK" DURATION="$DURATION" RTTS="$RTTS" unshare -rnm --propagation private "$0"
fi

BIN=$WORK/bin
export PATH="$BIN:$PATH"
LOG=$WORK/logs
mkdir -p "$LOG"
mount -t tmpfs tmpfs /run

pids=()
cleanup() {
	local rc=$?
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	if [[ $rc -ne 0 ]]; then
		echo "== FAILED (rc=$rc); logs:"
		for f in "$LOG"/*.log; do echo "--- $f"; tail -n 20 "$f"; done
	else
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() {
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

echo "== control server and machines"
export TC_CONTROL_DB=$WORK/control.db
tc-control users create perf >/dev/null
KEY=$(tc-control keys create -user perf -reusable -expiration 10m 2>/dev/null)
tc-control serve -listen 10.99.0.1:7740 -admin-listen "" -stun-listen 10.99.0.1:3478 -domain perf.internal >"$LOG/control.log" 2>&1 &
pids+=($!)
wait_for 5 "control listening" bash -c 'exec 3<>/dev/tcp/10.99.0.1/7740'
for n in a b; do
	ip netns exec "$n" tcd -state "$WORK/state-$n" -socket "/run/tc-$n.sock" -dns off >"$LOG/tcd-$n.log" 2>&1 &
	pids+=($!)
done
for n in a b; do wait_for 5 "tcd-$n socket" test -S "/run/tc-$n.sock"; done
tca() { ip netns exec a tc --socket /run/tc-a.sock "$@"; }
tca up --server http://10.99.0.1:7740 --authkey "$KEY" --hostname alpha >/dev/null
ip netns exec b tc --socket /run/tc-b.sock up --server http://10.99.0.1:7740 --authkey "$KEY" --hostname beta >/dev/null
IPB=$(ip netns exec b tc --socket /run/tc-b.sock ip -4)
wait_for 10 "alpha → beta" ip netns exec a ping -c1 -W1 "$IPB"

# The measuring server listens on all of beta's addresses.
ip netns exec b tput -listen :9000 2>"$LOG/tput-server.log" &
pids+=($!)
sleep 0.3

measure() { # measure LABEL ADDR
	local label=$1 addr=$2 tp rtt
	tp=$(ip netns exec a tput -connect "$addr:9000" -stream "$DURATION")
	rtt=$(ip netns exec a tput -connect "$addr:9000" -rtt "$RTTS")
	printf "%-22s %-28s %s\n" "$label" "$tp" "$rtt"
	RESULT_MBPS=${tp%% MB/s*}
}

echo "== results ($DURATION per throughput test, $RTTS round trips)"
printf "%-22s %-28s %s\n" "path" "throughput" "TCP round trip"
measure "underlay (no tunnel)" 10.99.0.3

wait_for 10 "direct path" bash -c "ip netns exec a ping -c1 -W1 $IPB >/dev/null; ip netns exec a tc --socket /run/tc-a.sock status | grep -q 'beta.*direct'"
measure "tunnel, direct" "$IPB"
DIRECT=$RESULT_MBPS

# Block UDP between the machines (not to the server): the relay carries it.
ip netns exec a nft -f - <<-EOF
	table inet cut {
		chain o { type filter hook output priority 0; ip daddr 10.99.0.3 udp dport 1-65535 drop; }
		chain i { type filter hook input priority 0; ip saddr 10.99.0.3 udp sport 1-65535 drop; }
	}
EOF
wait_for 20 "relay path" bash -c "ip netns exec a ping -c1 -W1 $IPB >/dev/null && ip netns exec a tc --socket /run/tc-a.sock status | grep -q 'beta.*relay 1'"
measure "tunnel, relay" "$IPB"
RELAY=$RESULT_MBPS
ip netns exec a nft delete table inet cut

check() { # check NAME VALUE MIN
	if [[ -n "$3" ]] && awk -v v="$2" -v m="$3" 'BEGIN { exit !(v < m) }'; then
		fail "$1 throughput $2 MB/s is below the budget of $3 MB/s"
	fi
}
check direct "$DIRECT" "${MIN_DIRECT_MBPS:-}"
check relay "$RELAY" "${MIN_RELAY_MBPS:-}"
echo "== done"
