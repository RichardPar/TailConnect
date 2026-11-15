#!/bin/sh
# Keep a DuckDNS name pointing at this machine's public address: a small
# update script run by a systemd timer every 5 minutes.
#
#   sudo packaging/linux/duckdns.sh install NAME   # asks for the token (or set DUCKDNS_TOKEN)
#   sudo packaging/linux/duckdns.sh update         # update now and show the answer
#   packaging/linux/duckdns.sh status              # timer, last result, what the name resolves to
#   sudo packaging/linux/duckdns.sh uninstall
#
# NAME is your DuckDNS name: "tailconnect" or "tailconnect.duckdns.org".
# The token is kept in /etc/duckdns/duckdns.conf (root only) and passed to
# curl on standard input, so it never appears in the process list.
# See docs/duckdns.md.
set -eu

CONF_DIR=/etc/duckdns
CONF=$CONF_DIR/duckdns.conf
UPDATER=/usr/local/sbin/duckdns-update
UNIT_DIR=/etc/systemd/system

die() { echo "duckdns.sh: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo $0 $*)"; }

install_updater() {
	need_root install
	name=${1:-}
	[ -n "$name" ] || die "usage: sudo $0 install NAME   (your DuckDNS name, e.g. tailconnect)"
	name=${name%.duckdns.org}
	case $name in
	*[!a-z0-9-]* | "" | -* | *-) die "\"$name\" isn't a DuckDNS name: use letters, digits and '-' (e.g. tailconnect)" ;;
	esac
	command -v curl >/dev/null || die "curl is needed: install it first (apt install curl)"

	token=${DUCKDNS_TOKEN:-}
	if [ -z "$token" ]; then
		[ -t 0 ] || die "no token: set DUCKDNS_TOKEN, or run from a terminal to be asked"
		printf "DuckDNS token (from duckdns.org, top of the page; not shown): "
		stty -echo 2>/dev/null || true
		read -r token || true
		stty echo 2>/dev/null || true
		echo
	fi
	token=$(printf %s "$token" | tr -d '[:space:]')
	case $token in
	*[!0-9a-fA-F-]* | "") die "that doesn't look like a DuckDNS token (it looks like 1a2b3c4d-1a2b-...)" ;;
	esac

	install -d -m 700 "$CONF_DIR"
	umask 077
	printf 'DOMAIN=%s\nTOKEN=%s\n' "$name" "$token" >"$CONF"
	chmod 600 "$CONF"
	umask 022

	cat >"$UPDATER" <<'EOF'
#!/bin/sh
# Update the DuckDNS name in /etc/duckdns/duckdns.conf to this network's
# public address (installed by TailConnect's duckdns.sh).
set -eu
. /etc/duckdns/duckdns.conf
# ip= empty: DuckDNS uses the address the request comes from.
result=$(printf 'url = "https://www.duckdns.org/update?domains=%s&token=%s&ip="\n' "$DOMAIN" "$TOKEN" |
	curl -fsS --max-time 20 -K -)
if [ "$result" != OK ]; then
	echo "DuckDNS refused the update for $DOMAIN.duckdns.org (answer: $result): check DOMAIN and TOKEN in /etc/duckdns/duckdns.conf" >&2
	exit 1
fi
echo "$DOMAIN.duckdns.org updated"
EOF
	chmod 755 "$UPDATER"

	cat >"$UNIT_DIR/duckdns.service" <<EOF
[Unit]
Description=Update the DuckDNS address
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATER
EOF
	cat >"$UNIT_DIR/duckdns.timer" <<'EOF'
[Unit]
Description=Update the DuckDNS address every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
	systemctl daemon-reload
	if ! systemctl start duckdns.service; then
		journalctl -u duckdns.service -n 3 --no-pager -o cat >&2 || true
		die "the first update failed (see above); fix the token or name and run: sudo $0 install $name"
	fi
	systemctl enable --now duckdns.timer >/dev/null 2>&1
	echo "DuckDNS updater installed: $name.duckdns.org is updated every 5 minutes."
	echo "Check it any time:  $0 status"
}

update_now() {
	need_root update
	[ -x "$UPDATER" ] || die "not installed: sudo $0 install NAME"
	"$UPDATER"
}

status() {
	if [ ! -x "$UPDATER" ]; then
		echo "DuckDNS updater: not installed (sudo $0 install NAME)"
		return 0
	fi
	name=""
	if [ -r "$CONF" ]; then
		name=$(sed -n 's/^DOMAIN=//p' "$CONF" | tail -n 1)
		echo "DuckDNS updater: installed for $name.duckdns.org"
	else
		echo "DuckDNS updater: installed (run with sudo to see the name)"
	fi
	echo "Timer: $(systemctl is-enabled duckdns.timer 2>/dev/null || echo off), $(systemctl is-active duckdns.timer 2>/dev/null || true), every 5 minutes"
	last=$(journalctl -u duckdns.service -n 50 --no-pager -o cat 2>/dev/null | grep -E 'updated|refused|curl' | tail -n 1 || true)
	[ -n "$last" ] && echo "Last result: $last"
	if [ -n "${name:-}" ]; then
		addr=$(getent ahostsv4 "$name.duckdns.org" 2>/dev/null | awk 'NR==1{print $1}')
		echo "$name.duckdns.org resolves to: ${addr:-nothing}"
	fi
}

uninstall() {
	need_root uninstall
	systemctl disable --now duckdns.timer >/dev/null 2>&1 || true
	rm -f "$UNIT_DIR/duckdns.timer" "$UNIT_DIR/duckdns.service" "$UPDATER"
	rm -rf "$CONF_DIR"
	systemctl daemon-reload
	echo "DuckDNS updater removed (the name keeps its last address at DuckDNS)."
}

case ${1:-} in
install) shift; install_updater "$@" ;;
update) update_now ;;
status) status ;;
uninstall) uninstall ;;
*) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
