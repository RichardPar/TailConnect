#!/usr/bin/env bash
# End-to-end NAT traversal test: two nodes on separate private networks, each
# behind its own NAT router, must find a direct path by hole punching (STUN +
# disco + CallMeMaybe via the relay). Then MagicDNS: each node rewrites its
# own resolv.conf (bind-mounted over /etc/resolv.conf for lookups), so glibc
# resolves peer names, reverse lookups and, via forwarding, other names.
# Real TUN devices, nftables masquerade and ping inside network namespaces;
# no root needed if unprivileged user namespaces are enabled.
#
#   [ns a] 10.1.0.2 ── [ns ra] NAT 198.51.100.2 ──┐
#                                                 br0 198.51.100.1  ← tc-control :8080, STUN :3478
#   [ns b] 10.2.0.2 ── [ns rb] NAT 198.51.100.3 ──┘
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)

if [[ "${TC_E2E_INNER:-}" != 1 ]]; then
	WORK=$(mktemp -d "${TMPDIR:-/tmp}/tc-nat.XXXXXX")
	echo "== building into $WORK/bin"
	(cd "$ROOT" && go build -o "$WORK/bin/" ./cmd/tc-control ./cmd/tcd ./cmd/tc)
	if [[ $(id -u) -eq 0 ]]; then
		exec env TC_E2E_INNER=1 WORK="$WORK" unshare -nm --propagation private "$0"
	fi
	exec env TC_E2E_INNER=1 WORK="$WORK" unshare -rnm --propagation private "$0"
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
	sleep 0.5
	for p in "${pids[@]}"; do kill -9 "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	[[ -n "${KEEP_LOGS:-}" ]] && cp -r "$LOG/." "$KEEP_LOGS/" 2>/dev/null
	if [[ $rc -ne 0 ]]; then
		echo "== FAILED (rc=$rc); logs:"
		for f in "$LOG"/*.log; do echo "--- $f"; tail -n 30 "$f"; done
	else
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }
wait_for() {
	local t=$1 what=$2; shift 2
	for ((i = 0; i < t * 10; i++)); do
		if "$@" >/dev/null 2>&1; then return 0; fi
		sleep 0.1
	done
	fail "timed out waiting for: $what"
}

echo "== network: two private LANs behind separate NATs"
ip link set lo up
ip link add br0 type bridge
ip addr add 198.51.100.1/24 dev br0
ip link set br0 up
setup_site() { # setup_site NAME ROUTER_WAN_IP LAN_PREFIX
	local n=$1 wan=$2 lan=$3 r="r$1"
	ip netns add "$r"
	ip netns add "$n"
	ip -n "$r" link set lo up
	ip -n "$n" link set lo up
	# WAN: router ↔ internet bridge
	ip link add "$r-wan" type veth peer name "$r-br"
	ip link set "$r-br" master br0 up
	ip link set "$r-wan" netns "$r"
	ip -n "$r" addr add "$wan/24" dev "$r-wan"
	ip -n "$r" link set "$r-wan" up
	# LAN: router ↔ node
	ip link add "$r-lan" type veth peer name "$n-eth"
	ip link set "$r-lan" netns "$r"
	ip link set "$n-eth" netns "$n"
	ip -n "$r" addr add "$lan.1/24" dev "$r-lan"
	ip -n "$r" link set "$r-lan" up
	ip -n "$n" addr add "$lan.2/24" dev "$n-eth"
	ip -n "$n" link set "$n-eth" up
	ip -n "$n" route add default via "$lan.1"
	ip netns exec "$r" sysctl -qw net.ipv4.ip_forward=1
	# A typical home router (OpenWrt defaults): masquerade on WAN, and drop
	# unsolicited new connections from WAN, both to the router itself and
	# forwarded. Replies to outbound flows (including punched holes) pass.
	# Dropping in "input" also stops stray inbound packets from creating
	# conntrack entries that would make the NAT rewrite our ports.
	ip netns exec "$r" nft -f - <<-EOF
		table ip nat {
			chain post { type nat hook postrouting priority 100; oifname "$r-wan" masquerade; }
		}
		table inet fw {
			chain input { type filter hook input priority 0; policy accept;
				iifname "$r-wan" ct state established,related accept
				iifname "$r-wan" drop
			}
			chain forward { type filter hook forward priority 0; policy accept;
				iifname "$r-wan" ct state established,related accept
				iifname "$r-wan" drop
			}
		}
	EOF
}
setup_site a 198.51.100.2 10.1.0
setup_site b 198.51.100.3 10.2.0
ip netns exec a ping -c1 -W2 198.51.100.1 >/dev/null || fail "site a cannot reach the internet bridge"
ip netns exec b ping -c1 -W2 198.51.100.1 >/dev/null || fail "site b cannot reach the internet bridge"
ip netns exec a ping -c1 -W1 10.2.0.2 >/dev/null 2>&1 && fail "private networks should not route to each other"
ok "two NATed sites; no direct route between private networks"

echo "== upstream DNS (stands in for each site's ISP resolver)"
python3 -I "$ROOT/tests/e2e/fakedns.py" 198.51.100.1 192.0.2.53 >"$LOG/fakedns.log" 2>&1 &
pids+=($!)
for n in a b; do
	printf 'nameserver 198.51.100.1\nsearch corp.example\noptions edns0\n' >"$WORK/resolv-$n.conf"
	cp "$WORK/resolv-$n.conf" "$WORK/resolv-$n.orig"
done
# Lookups bind-mount a node's resolv.conf over /etc/resolv.conf. If that is
# a symlink into /run (systemd-resolved), the target must exist in our tmpfs.
target=$(readlink -m /etc/resolv.conf)
if [[ $target == /run/* ]]; then mkdir -p "$(dirname "$target")"; : >"$target"; fi
lookup() { # lookup NODE CMD... — run CMD in NODE's netns with NODE's resolv.conf
	local n=$1; shift
	ip netns exec "$n" unshare -m --propagation private sh -c 'mount --bind "$1" /etc/resolv.conf && shift && exec "$@"' sh "$WORK/resolv-$n.conf" "$@"
}

echo "== control server (relay + STUN)"
export TC_CONTROL_DB=$WORK/control.db
tc-control users create alice >/dev/null
KEY=$(tc-control keys create -user alice -reusable -expiration 10m 2>/dev/null)
tc-control serve -listen 198.51.100.1:8080 -admin-listen "" -stun-listen 198.51.100.1:3478 -domain nat.internal >"$LOG/control.log" 2>&1 &
pids+=($!)
wait_for 5 "control listening" bash -c 'exec 3<>/dev/tcp/198.51.100.1/8080'
ok "tc-control up"

if [[ -n "${TC_NAT_PCAP:-}" ]]; then
	for r in ra rb; do
		python3 -I "$ROOT/tests/e2e/udpsniff.py" "$r-br" 3478 >"$LOG/$r-wan.pcap.txt" 2>&1 &
		pids+=($!)
	done
fi

echo "== daemons"
declare -A tcdpid
for n in a b; do
	ip netns exec "$n" env TC_DISCO_DEBUG=${TC_DISCO_DEBUG:-} tcd -state "$WORK/state-$n" -socket "/run/tc-$n.sock" \
		-resolv-conf "$WORK/resolv-$n.conf" >"$LOG/tcd-$n.log" 2>&1 &
	pids+=($!)
	tcdpid[$n]=$!
done
for n in a b; do wait_for 5 "tcd-$n socket" test -S "/run/tc-$n.sock"; done
tca() { ip netns exec a tc --socket /run/tc-a.sock "$@"; }
tcb() { ip netns exec b tc --socket /run/tc-b.sock "$@"; }
tca up --server http://198.51.100.1:8080 --authkey "$KEY" --hostname alpha
tcb up --server http://198.51.100.1:8080 --authkey "$KEY" --hostname beta
IPA=$(tca ip -4); IPB=$(tcb ip -4)

echo "== STUN: public addresses"
wait_for 10 "alpha learns its public address" bash -c "ip netns exec a tc --socket /run/tc-a.sock status --json | grep -q '198.51.100.2:'"
wait_for 10 "beta learns its public address" bash -c "ip netns exec b tc --socket /run/tc-b.sock status --json | grep -q '198.51.100.3:'"
ok "each node advertises its NAT's public address"

echo "== traffic and hole punching"
t0=$(date +%s)
wait_for 15 "alpha → beta ping" ip netns exec a ping -c1 -W1 "$IPB"
ok "alpha → beta works ($(( $(date +%s) - t0 ))s)"
wait_for 15 "direct path through both NATs" bash -c "ip netns exec a ping -c1 -W1 $IPB >/dev/null; ip netns exec a tc --socket /run/tc-a.sock status | grep -q 'direct 198.51.100.3:'"
ok "hole punched: alpha → beta is direct via beta's NAT ($(( $(date +%s) - t0 ))s after first packet)"
ip netns exec b ping -c3 -i0.2 -W1 "$IPA" >/dev/null || fail "beta → alpha"
tcb status | grep -q "direct 198.51.100.2:" || { tcb status; fail "beta → alpha not direct"; }
ok "beta → alpha is direct via alpha's NAT"
ip netns exec a ping -c20 -i0.1 -W1 "$IPB" >/dev/null || fail "direct path unstable"
ok "direct path stable"
tca status

echo "== MagicDNS"
for n in a b; do
	wait_for 5 "$n's resolv.conf points at MagicDNS" grep -q '^nameserver 100.100.100.100$' "$WORK/resolv-$n.conf"
done
grep -q '^search nat.internal corp.example$' "$WORK/resolv-a.conf" || { cat "$WORK/resolv-a.conf"; fail "search domains"; }
ok "resolv.conf rewritten (original search domain kept)"
tca status | grep -q '^MagicDNS: nat.internal (file, all names)' || { tca status; fail "tc status MagicDNS line"; }
got=$(lookup a getent ahostsv4 beta | awk 'NR==1{print $1}')
[[ $got == "$IPB" ]] || fail "short name beta resolved to '$got', want $IPB"
got=$(lookup b getent ahostsv4 alpha.nat.internal | awk 'NR==1{print $1}')
[[ $got == "$IPA" ]] || fail "alpha.nat.internal resolved to '$got', want $IPA"
ok "peer names resolve through glibc (beta → $IPB, alpha.nat.internal → $IPA)"
lookup a getent hosts "$IPB" | grep -q 'beta.nat.internal' || fail "reverse lookup of $IPB"
ok "reverse lookup: $IPB → beta.nat.internal"
lookup a getent ahostsv4 gamma.nat.internal >/dev/null && fail "unknown MagicDNS name should not resolve"
ok "unknown names under nat.internal: not found (not forwarded)"
got=$(lookup a getent ahostsv4 www.example.com | awk 'NR==1{print $1}')
[[ $got == 192.0.2.53 ]] || fail "www.example.com resolved to '$got', want 192.0.2.53 from the upstream"
ok "other names forwarded to the original resolver"
lookup a ping -c1 -W2 beta >/dev/null || fail "ping beta by name"
ok "ping beta (by name) works"

echo "== direct path dies: fall back to relay, then recover"
# Drop all UDP between the two NATs (both still reach control and the relay).
ip netns exec ra nft -f - <<-EOF
	table ip cut {
		chain block { type filter hook forward priority -10; policy accept;
			ip daddr 198.51.100.3 udp dport != 3478 drop
			ip saddr 198.51.100.3 drop
		}
	}
EOF
t0=$(date +%s)
wait_for 20 "alpha → beta via relay" bash -c "ip netns exec a ping -c1 -W1 $IPB >/dev/null && ip netns exec a tc --socket /run/tc-a.sock status | grep -q 'relay 1'"
ok "fell back to relay ($(( $(date +%s) - t0 ))s)"
ip netns exec ra nft delete table ip cut
t0=$(date +%s)
wait_for 20 "direct again" bash -c "ip netns exec a ping -c1 -W1 $IPB >/dev/null; ip netns exec a tc --socket /run/tc-a.sock status | grep -q 'direct 198.51.100.3:'"
ok "direct path recovered ($(( $(date +%s) - t0 ))s)"

echo "== stopping tcd restores resolv.conf"
kill "${tcdpid[a]}"
wait_for 5 "tcd-a exits" bash -c "! kill -0 ${tcdpid[a]}"
cmp -s "$WORK/resolv-a.orig" "$WORK/resolv-a.conf" || { cat "$WORK/resolv-a.conf"; fail "resolv.conf not restored"; }
[[ ! -e "$WORK/state-a/resolv.conf.backup" ]] || fail "backup left behind"
ok "original resolv.conf restored"

echo "== PASS"
