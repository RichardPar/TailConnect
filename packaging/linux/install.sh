#!/bin/sh
# Install or remove TailConnect on a systemd Linux host.
#
#   sudo packaging/linux/install.sh client            # tcd + tc, start tcd
#   sudo packaging/linux/install.sh server            # tc-control, start it
#   sudo packaging/linux/install.sh relay             # tc-relay binary only
#   sudo packaging/linux/install.sh uninstall-client [--purge]
#   sudo packaging/linux/install.sh uninstall-server [--purge]
#
# Binaries are taken from bin/ at the top of the source tree or release
# tarball (override with BIN_DIR=...). Running "client" or "server" again
# upgrades in place and restarts the service; settings in /etc/default and
# data in /var/lib are kept. --purge also deletes settings and data.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
BIN_DIR=${BIN_DIR:-$TOP/bin}
PREFIX=${PREFIX:-/usr/local}
UNIT_DIR=/etc/systemd/system
DOC_DIR=$PREFIX/share/doc/tailconnect

die() { echo "install.sh: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo $0 $*)"; }
need_bin() {
	for b in "$@"; do
		[ -x "$BIN_DIR/$b" ] || die "$BIN_DIR/$b not found; build first (make build) or set BIN_DIR"
	done
}
install_docs() {
	install -d "$DOC_DIR"
	[ -f "$TOP/README.md" ] && install -m644 "$TOP/README.md" "$DOC_DIR/"
	[ -d "$TOP/docs" ] && cp -r "$TOP/docs" "$DOC_DIR/"
	return 0
}
# install_default NAME: settings file, only if not already there.
install_default() {
	if [ ! -e "/etc/default/$1" ]; then
		install -m644 "$HERE/$1.default" "/etc/default/$1"
		echo "created /etc/default/$1"
	fi
}
# drop_docs: remove the docs once no TailConnect binary is left.
drop_docs() {
	for b in tcd tc-control tc-relay; do [ -e "$PREFIX/bin/$b" ] && return 0; done
	rm -rf "${DOC_DIR:?}"
}
# start UNIT: enable and (re)start, so an upgrade picks up new binaries.
start() {
	systemctl daemon-reload
	systemctl enable "$1" >/dev/null 2>&1
	systemctl restart "$1"
	sleep 1
	systemctl is-active --quiet "$1" || {
		journalctl -u "$1" -n 20 --no-pager >&2
		die "$1 failed to start (log above)"
	}
}

cmd=${1:-}
purge=no
[ "${2:-}" = "--purge" ] && purge=yes

case "$cmd" in
client)
	need_root "$cmd"
	need_bin tcd tc
	install -m755 "$BIN_DIR/tcd" "$BIN_DIR/tc" "$PREFIX/bin/"
	install -m644 "$HERE/tcd.service" "$UNIT_DIR/"
	install_default tcd
	install_docs
	start tcd
	echo "tcd is running ($("$PREFIX/bin/tcd" -version))."
	if "$PREFIX/bin/tc" status 2>/dev/null | grep -q '^Logged out'; then
		echo "Join the network:  sudo tc up --server http://SERVER:7740 --authkey tc-auth-..."
	else
		"$PREFIX/bin/tc" status | head -2
	fi
	;;
server)
	need_root "$cmd"
	need_bin tc-control
	install -m755 "$BIN_DIR/tc-control" "$PREFIX/bin/"
	install -m644 "$HERE/tc-control.service" "$UNIT_DIR/"
	install_default tc-control
	install_docs
	start tc-control
	echo "tc-control is running ($("$PREFIX/bin/tc-control" version))."
	echo "Next (once): sudo tc-control users create NAME"
	echo "             sudo tc-control keys create -user NAME -reusable -expiration 24h"
	echo "             sudo tc-control admin-token      # for the admin UI on http://127.0.0.1:7741"
	;;
relay)
	need_root "$cmd"
	need_bin tc-relay
	install -m755 "$BIN_DIR/tc-relay" "$PREFIX/bin/"
	echo "installed $PREFIX/bin/tc-relay (see docs/configuration.md#tc-relay to run it)"
	;;
uninstall-client)
	need_root "$cmd"
	# Stopping tcd removes the interface and restores DNS settings. The node
	# stays registered; run `tc logout` first to remove it from the network.
	systemctl disable --now tcd 2>/dev/null || true
	rm -f "$UNIT_DIR/tcd.service" "$PREFIX/bin/tcd" "$PREFIX/bin/tc"
	systemctl daemon-reload
	drop_docs
	if [ "$purge" = yes ]; then
		rm -rf /var/lib/tailconnect /etc/default/tcd /etc/systemd/system/tcd.service.d
		echo "removed tcd, its keys and settings"
	else
		echo "removed tcd (keys kept in /var/lib/tailconnect, settings in /etc/default/tcd; --purge deletes them)"
	fi
	;;
uninstall-server)
	need_root "$cmd"
	systemctl disable --now tc-control 2>/dev/null || true
	rm -f "$UNIT_DIR/tc-control.service" "$PREFIX/bin/tc-control"
	systemctl daemon-reload
	drop_docs
	if [ "$purge" = yes ]; then
		rm -rf /var/lib/private/tc-control /var/lib/tc-control /etc/default/tc-control /etc/systemd/system/tc-control.service.d
		echo "removed tc-control, its database and settings"
	else
		echo "removed tc-control (database kept in /var/lib/tc-control, settings in /etc/default/tc-control; --purge deletes them)"
	fi
	;;
*)
	sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
	;;
esac
