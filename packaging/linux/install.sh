#!/bin/sh
# Install or remove TailConnect on a systemd Linux host.
#
#   sudo packaging/linux/install.sh server            # tc-control: asks a few questions, then starts it
#   sudo packaging/linux/install.sh client            # tcd + tc (+ the desktop app): asks for the server and a key, then joins
#   sudo packaging/linux/install.sh relay             # tc-relay binary only
#   sudo packaging/linux/install.sh uninstall-client [--purge]
#   sudo packaging/linux/install.sh uninstall-server [--purge]
#
# A first install from a terminal asks its questions and writes the settings
# (no files to edit). Running it again upgrades in place and keeps settings
# (in /etc/default) and data (in /var/lib).
#
#   --reconfigure   ask the questions again (server: change its settings;
#                   client: join a server, e.g. a different one)
#   --no-setup      never ask (for scripts); then configure by hand
#   --purge         (uninstall) also delete settings and data
#
# Binaries are taken from bin/ at the top of the source tree or release
# tarball (override with BIN_DIR=...).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
BIN_DIR=${BIN_DIR:-$TOP/bin}
PREFIX=${PREFIX:-/usr/local}
UNIT_DIR=/etc/systemd/system
DEFAULTS=${DEFAULTS:-/etc/default}
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
	[ -f "$TOP/QUICKSTART.md" ] && install -m644 "$TOP/QUICKSTART.md" "$DOC_DIR/"
	[ -d "$TOP/docs" ] && cp -r "$TOP/docs" "$DOC_DIR/"
	return 0
}
# install_default NAME: settings file, only if not already there.
install_default() {
	if [ ! -e "$DEFAULTS/$1" ]; then
		install -m644 "$HERE/$1.default" "$DEFAULTS/$1"
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

# ---- questions ----

# interactive: ask questions only on a terminal, unless told not to.
interactive() { [ "$setup" != no ] && [ -t 0 ] && [ -t 1 ]; }

# ask VAR "Question" [DEFAULT]: read an answer (DEFAULT if empty).
ask() {
	if [ -n "${3:-}" ]; then printf '%s [%s]: ' "$2" "$3"; else printf '%s: ' "$2"; fi
	read -r _ans || _ans=
	[ -n "$_ans" ] || _ans=${3:-}
	eval "$1=\$_ans"
}

# ask_secret VAR "Question": like ask, without echoing.
ask_secret() {
	printf '%s: ' "$2"
	stty -echo 2>/dev/null || true
	read -r _ans || _ans=
	stty echo 2>/dev/null || true
	echo
	eval "$1=\$_ans"
}

# yesno "Question" y|n: succeeds for yes.
yesno() {
	ask _yn "$1 (y/n)" "$2"
	case $_yn in [Yy]*) return 0 ;; *) return 1 ;; esac
}

# valid_dns NAME: lowercase labels separated by dots, at least two labels.
valid_dns() {
	case $1 in
	*[!a-z0-9.-]* | .* | *. | *..* | -* | *-) return 1 ;;
	*.*) return 0 ;;
	*) return 1 ;;
	esac
}

# valid_account NAME: 1-32 lowercase letters, digits or '-'.
valid_account() {
	case $1 in
	"" | *[!a-z0-9-]* | -* | *-) return 1 ;;
	esac
	[ ${#1} -le 32 ]
}

# lan_address: this machine's main IPv4 address.
lan_address() {
	ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1
}

# default_account: a starting point for the operator's account name.
default_account() {
	n=$(printf '%s' "${SUDO_USER:-admin}" | tr 'A-Z_' 'a-z-' | tr -cd 'a-z0-9-')
	valid_account "$n" && echo "$n" || echo admin
}

# open_ports PORT/PROTO...: offer to open them in an active firewall.
open_ports() {
	if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
		if yesno "Open $* in the firewall (ufw)?" y; then
			for p in "$@"; do ufw allow "$p" >/dev/null; done
			echo "  opened $*"
		fi
	elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		if yesno "Open $* in the firewall (firewalld)?" y; then
			for p in "$@"; do firewall-cmd --quiet --permanent --add-port="$p"; done
			firewall-cmd --quiet --reload
			echo "  opened $*"
		fi
	else
		echo "  If this machine or your network has a firewall, open: $*"
	fi
}

# ---- server setup ----

# server_questions: sets server_args (for tc-control serve), server_url
# (what devices use) and server_ports (to open).
server_questions() {
	echo
	echo "== Server settings"
	echo "Machines are named NAME.ACCOUNT.DOMAIN, e.g. laptop.alice.home.internal."
	echo "Pick the domain now: changing it later renames every machine."
	while :; do
		ask domain "MagicDNS domain" "home.internal"
		valid_dns "$domain" && break
		echo "  Use lowercase letters, digits, '-' and dots, with at least one dot (e.g. home.internal)."
	done
	echo
	echo "Where will your devices reach this server?"
	echo "  1) Only on this LAN: no public name needed (devices away from home can't connect)"
	echo "  2) From anywhere, over HTTPS: needs a DNS name pointing here, and port 443 reachable"
	echo "     from the internet (a free certificate comes from Let's Encrypt automatically)"
	while :; do
		ask where "Choose 1 or 2" "1"
		case $where in 1 | 2) break ;; esac
	done
	if [ "$where" = 1 ]; then
		ask addr "This server's address on the LAN (give it a fixed address on your router)" "$(lan_address)"
		[ -n "$addr" ] || die "no address given"
		server_url="http://$addr:7740"
		server_args="-domain $domain -public-url $server_url"
		server_ports="7740/tcp 3478/udp"
		portal_questions "http://$addr:7741" "plain HTTP: passwords typed into it cross your network unencrypted"
		return
	fi
	while :; do
		ask name "DNS name for this server (e.g. vpn.example.com)"
		valid_dns "$name" && break
		echo "  That isn't a DNS name."
	done
	resolved=$(getent ahostsv4 "$name" 2>/dev/null | awk '{print $1; exit}')
	if [ -n "$resolved" ]; then
		echo "  $name points at $resolved: it must be this server's public address."
	else
		echo "  $name doesn't resolve yet. Point it at this server's public address before devices join;"
		echo "  the certificate is fetched on the first connection."
	fi
	echo "Let's Encrypt checks the name on port 443 (or 80). Use 443 unless something else needs it."
	while :; do
		ask port "HTTPS port" "443"
		case $port in '' | *[!0-9]*) ;; *) [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && break ;; esac
	done
	ask email "Email for your Let's Encrypt account (optional)" ""
	case $email in *[!a-zA-Z0-9@._+-]*) die "that doesn't look like an email address" ;; esac
	server_args="-domain $domain -listen :$port -acme-domain $name"
	server_url="https://$name"
	server_ports="$port/tcp 3478/udp"
	if [ "$port" != 443 ]; then
		server_args="$server_args -acme-http-listen :80"
		server_url="$server_url:$port"
		server_ports="$server_ports 80/tcp"
	fi
	[ -z "$email" ] || server_args="$server_args -acme-email $email"
	portal_questions "https://$name:7741" "HTTPS, with the same certificate"
}

# portal_questions URL NOTE: where the web portal listens. Sets portal_url
# ("" when it's only on this machine) and adds to server_args/server_ports.
portal_questions() {
	echo
	echo "The web portal (port 7741) is where you manage accounts, machines and keys. Who may open it?"
	echo "  1) Anyone who can reach this server; they still need to sign in ($2)"
	echo "  2) Only this machine: from your computer, through an SSH tunnel"
	while :; do
		ask portal "Choose 1 or 2" "1"
		case $portal in 1 | 2) break ;; esac
	done
	if [ "$portal" = 1 ]; then
		portal_url=$1
		server_ports="$server_ports 7741/tcp"
	else
		portal_url=
		server_args="$server_args -admin-listen 127.0.0.1:7741"
	fi
}

# portal_hint: how to open the portal, from the saved settings.
portal_hint() {
	if grep -q -- '-admin-listen 127.0.0.1' "$DEFAULTS/tc-control" 2>/dev/null; then
		echo "Web portal: only on this machine; from your computer: ssh -L 7741:127.0.0.1:7741 ${SUDO_USER:-you}@$(hostname), then open http://localhost:7741"
	elif grep -q -- '-admin-listen ""' "$DEFAULTS/tc-control" 2>/dev/null; then
		echo "Web portal: turned off (-admin-listen \"\")"
	else
		echo "Web portal: port 7741 on this server, e.g. http://$(lan_address):7741 (https:// with automatic HTTPS)"
	fi
}

# write_server_settings ARGS: put ARGS in /etc/default/tc-control,
# keeping a copy of the previous file.
write_server_settings() {
	f=$DEFAULTS/tc-control
	[ -e "$f" ] && cp -p "$f" "$f.bak"
	install -m644 "$HERE/tc-control.default" "$f"
	sed -i "s|^TC_CONTROL_ARGS=.*|TC_CONTROL_ARGS=\"$1\"|" "$f"
	echo "  saved in $f"
}

# operator_name: the first active operator who can sign in ("" if none).
operator_name() {
	"$PREFIX/bin/tc-control" users list 2>/dev/null |
		awk 'NR > 1 && $3 == "operator" && $4 == "active" && $5 == "yes" { print $2; exit }'
}

# server_finish URL: the operator's account, a join key, and how to join.
server_finish() {
	url=$1
	admin=$(operator_name)
	if [ -z "$admin" ]; then
		echo
		echo "== Your account"
		echo "You sign in to the web portal with it, and your devices join it. It's an operator"
		echo "account: it can also manage the server and other people's accounts."
		while :; do
			ask admin "Account name" "$(default_account)"
			valid_account "$admin" && break
			echo "  Use 1-32 lowercase letters, digits or '-'."
		done
		echo "Choose a password (at least 10 characters)."
		n=0
		until "$PREFIX/bin/tc-control" users create "$admin" -operator -password >/dev/null; do
			n=$((n + 1))
			[ "$n" -lt 3 ] || die "no account created; later: sudo tc-control users create $admin -operator -password"
			echo "  Try again."
		done
		echo "  created $admin"
	fi
	key=$("$PREFIX/bin/tc-control" keys create -user "$admin" -reusable -expiration 24h 2>/dev/null)
	echo
	echo "== Ready"
	echo "Join your devices with this key. It works for 24 hours, on any number of devices:"
	echo
	echo "  $key"
	echo
	echo "  Linux:    sudo ./packaging/linux/install.sh client     (asks for the server and the key)"
	echo "  Android:  in the TailConnect app, Server: $url  and the key above"
	echo "  Server URL for devices: $url"
	echo
	if [ -n "${portal_url:-}" ]; then
		echo "Web portal: $portal_url   (sign in as $admin)"
	else
		echo "Web portal: from your computer, ssh -L 7741:127.0.0.1:7741 ${SUDO_USER:-you}@$(hostname)"
		echo "  then open http://localhost:7741 and sign in as $admin"
	fi
	echo "More keys: sudo tc-control keys create -user $admin   (or Auth keys in the portal)"
}

# ---- client setup ----

GUI_FILES="$PREFIX/bin/tc-gui $PREFIX/share/applications/tailconnect.desktop /etc/xdg/autostart/tailconnect.desktop
	/usr/share/polkit-1/actions/org.tailconnect.gui.policy $PREFIX/share/icons/hicolor/256x256/apps/tailconnect.png"

# install_gui: the desktop app (tc-gui), where there is a desktop (GTK 3).
# Members of the tailconnect group may connect and disconnect; the user who
# ran sudo is added to it.
install_gui() {
	[ -x "$BIN_DIR/tc-gui" ] || return 0
	if ! ldconfig -p 2>/dev/null | grep -q 'libgtk-3\.so\.0'; then
		echo "No desktop (GTK 3) found: skipped the TailConnect app."
		return 0
	fi
	install -m755 "$BIN_DIR/tc-gui" "$PREFIX/bin/"
	install -d "$PREFIX/share/applications" "$PREFIX/share/icons/hicolor/256x256/apps" /etc/xdg/autostart /usr/share/polkit-1/actions
	"$PREFIX/bin/tc-gui" -icon "$PREFIX/share/icons/hicolor/256x256/apps/tailconnect.png"
	sed "s|@PREFIX@|$PREFIX|g" "$HERE/tailconnect.desktop" >"$PREFIX/share/applications/tailconnect.desktop"
	sed "s|@PREFIX@|$PREFIX|g" "$HERE/tailconnect-autostart.desktop" >/etc/xdg/autostart/tailconnect.desktop
	sed "s|@PREFIX@|$PREFIX|g" "$HERE/org.tailconnect.gui.policy" >/usr/share/polkit-1/actions/org.tailconnect.gui.policy
	chmod 644 "$PREFIX/share/applications/tailconnect.desktop" /etc/xdg/autostart/tailconnect.desktop /usr/share/polkit-1/actions/org.tailconnect.gui.policy
	command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t "$PREFIX/share/icons/hicolor" 2>/dev/null || true
	getent group tailconnect >/dev/null || groupadd --system tailconnect
	if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
		if ! id -nG "$SUDO_USER" | tr ' ' '\n' | grep -qx tailconnect; then
			usermod -aG tailconnect "$SUDO_USER"
			echo "Added $SUDO_USER to the tailconnect group (may connect and disconnect)."
		fi
	fi
	echo "TailConnect app installed: open it from the applications menu; it starts at login."
	echo "  Others who may connect/disconnect:  sudo usermod -aG tailconnect NAME"
}

client_join() {
	echo
	echo "== Join a network"
	echo "The server URL and an auth key come from whoever runs the server"
	echo "(sudo tc-control keys create -user NAME, or Auth keys in the web portal)."
	tries=0
	while :; do
		while :; do
			ask url "Server URL (e.g. http://192.168.1.10:7740 or https://vpn.example.com)" "${url:-}"
			case $url in http://?* | https://?*) break ;; esac
			echo "  Start it with http:// or https://"
			url=
		done
		ask_secret key "Auth key (tc-auth-…; input hidden)"
		ask host "Name for this device" "${host:-$(hostname | tr 'A-Z' 'a-z')}"
		if TC_AUTHKEY=$key "$PREFIX/bin/tc" up --server "$url" --hostname "$host"; then
			echo
			"$PREFIX/bin/tc" status | head -n 6
			return 0
		fi
		tries=$((tries + 1))
		if [ "$tries" -ge 3 ] || ! yesno "Try again?" y; then
			echo "Join later with:  sudo tc up --server URL --authkey KEY"
			return 0
		fi
	done
}

# ---- commands ----

main() {
	cmd=${1:-}
	[ $# -gt 0 ] && shift
	purge=no setup=auto
	for a in "$@"; do
		case $a in
		--purge) purge=yes ;;
		--reconfigure) setup=always ;;
		--no-setup) setup=no ;;
		*) die "unknown option $a" ;;
		esac
	done

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
		install_gui
		joined=yes
		"$PREFIX/bin/tc" status 2>/dev/null | grep -q '^Logged out' && joined=no
		if interactive && { [ "$joined" = no ] || [ "$setup" = always ]; }; then
			client_join
		elif [ "$joined" = no ]; then
			echo "Join the network:  sudo tc up --server URL --authkey tc-auth-..."
		else
			"$PREFIX/bin/tc" status | head -n 2
		fi
		;;
	server)
		need_root "$cmd"
		need_bin tc-control
		first=no
		[ -e "$DEFAULTS/tc-control" ] || first=yes
		install -m755 "$BIN_DIR/tc-control" "$PREFIX/bin/"
		install -m644 "$HERE/tc-control.service" "$UNIT_DIR/"
		install_default tc-control
		install_docs
		if interactive && { [ "$first" = yes ] || [ "$setup" = always ]; }; then
			server_questions
			write_server_settings "$server_args"
			start tc-control
			echo "tc-control is running ($("$PREFIX/bin/tc-control" version))."
			open_ports $server_ports
			server_finish "$server_url"
		else
			start tc-control
			echo "tc-control is running ($("$PREFIX/bin/tc-control" version)); settings in $DEFAULTS/tc-control."
			[ "$first" = yes ] || echo "To change its settings:  sudo $0 server --reconfigure"
			if [ -z "$(operator_name)" ]; then
				echo "Next (once): sudo tc-control users create NAME -operator -password   # your account for the web portal"
				echo "             sudo tc-control keys create -user NAME -reusable -expiration 24h"
			fi
			portal_hint
		fi
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
		rm -f "$UNIT_DIR/tcd.service" "$PREFIX/bin/tcd" "$PREFIX/bin/tc" $GUI_FILES
		pkill -x tc-gui 2>/dev/null || true
		systemctl daemon-reload
		drop_docs
		if [ "$purge" = yes ]; then
			rm -rf /var/lib/tailconnect "$DEFAULTS/tcd" /etc/systemd/system/tcd.service.d
			getent group tailconnect >/dev/null && groupdel tailconnect
			echo "removed tcd, its keys and settings"
		else
			echo "removed tcd (keys kept in /var/lib/tailconnect, settings in $DEFAULTS/tcd; --purge deletes them)"
		fi
		;;
	uninstall-server)
		need_root "$cmd"
		systemctl disable --now tc-control 2>/dev/null || true
		rm -f "$UNIT_DIR/tc-control.service" "$PREFIX/bin/tc-control"
		systemctl daemon-reload
		drop_docs
		if [ "$purge" = yes ]; then
			rm -rf /var/lib/private/tc-control /var/lib/tc-control "$DEFAULTS/tc-control" "$DEFAULTS/tc-control.bak" /etc/systemd/system/tc-control.service.d
			echo "removed tc-control, its database and settings"
		else
			echo "removed tc-control (database kept in /var/lib/tc-control, settings in $DEFAULTS/tc-control; --purge deletes them)"
		fi
		;;
	*)
		sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
		exit 2
		;;
	esac
}

# TC_INSTALL_LIB=1 loads the functions without running anything (tests).
[ "${TC_INSTALL_LIB:-}" = 1 ] || main "$@"
