#!/bin/sh
# Switch tc-control to HTTPS with a free Let's Encrypt certificate for a DNS
# name. tc-control gets and renews the certificate itself; this script only
# changes its settings, restarts it and checks.
#
#   sudo packaging/linux/letsencrypt.sh NAME [options]
#   sudo packaging/linux/letsencrypt.sh --restore     # put the previous settings back
#
#   --port N         port tc-control listens on (default 443)
#   --public-port N  port devices connect to, when the router forwards
#                    another outside port to --port (e.g. 8443 to 7740)
#   --email ADDR     contact address for Let's Encrypt (optional)
#   --staging        use Let's Encrypt's test service first (untrusted
#                    certificates, generous limits); run again without it after
#   --no-dns         for a DuckDNS name: let Let's Encrypt connect in on port
#                    443 or 80 instead of checking through DuckDNS
#   --dry-run        show the new settings without changing anything
#
# How Let's Encrypt checks the name is yours:
#   NAME.duckdns.org  through DuckDNS (a TXT record): no port needs to be open
#                     for it. Uses the token from duckdns.sh, or $DUCKDNS_TOKEN,
#                     or asks.
#   any other name    it connects in: TCP 443 must reach this machine (or,
#                     with another --port, TCP 80 too).
# Devices need nothing but the URL: only the server has a certificate.
# See docs/duckdns.md and docs/lets-encrypt.md.
set -eu

DEFAULTS=${DEFAULTS:-/etc/default}
SETTINGS=$DEFAULTS/tc-control
STATE_DIR=${STATE_DIR:-/var/lib/tc-control}
DUCKDNS_CONF=${DUCKDNS_CONF:-/etc/duckdns/duckdns.conf}

die() { echo "letsencrypt.sh: $*" >&2; exit 1; }
usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

name="" port=443 public_port="" email="" staging=no dry=no restore=no nodns=no
while [ $# -gt 0 ]; do
	case $1 in
	--port) [ $# -ge 2 ] || usage; port=$2; shift ;;
	--port=*) port=${1#*=} ;;
	--public-port) [ $# -ge 2 ] || usage; public_port=$2; shift ;;
	--public-port=*) public_port=${1#*=} ;;
	--email) [ $# -ge 2 ] || usage; email=$2; shift ;;
	--email=*) email=${1#*=} ;;
	--staging) staging=yes ;;
	--no-dns) nodns=yes ;;
	--dry-run) dry=yes ;;
	--restore) restore=yes ;;
	-h | --help) usage ;;
	-*) die "unknown option $1 (see $0 --help)" ;;
	*) [ -z "$name" ] || usage; name=$1 ;;
	esac
	shift
done

[ "$dry" = yes ] || [ "$(id -u)" -eq 0 ] || die "run as root (sudo $0 ...)"
[ -f "$SETTINGS" ] || die "$SETTINGS not found: install the server first (install.sh server)"

if [ "$restore" = yes ]; then
	last=$(ls -1t "$SETTINGS".pre-letsencrypt-* 2>/dev/null | head -n 1 || true)
	[ -n "$last" ] || die "no backup of the settings ($SETTINGS.pre-letsencrypt-*)"
	cp -p "$last" "$SETTINGS"
	systemctl restart tc-control
	echo "Restored $last and restarted tc-control:"
	grep '^TC_CONTROL_ARGS=' "$SETTINGS"
	echo "Devices that moved to the HTTPS name need moving back: sudo tc up --server <old URL>"
	exit 0
fi

[ -n "$name" ] || usage
name=$(printf %s "$name" | tr 'A-Z' 'a-z')
name=${name%.}
case $name in
*.*) ;;
*) die "\"$name\" isn't a full DNS name (e.g. tailconnect.duckdns.org)" ;;
esac
case $name in
*[!a-z0-9.-]* | .* | *..*) die "\"$name\" isn't a valid DNS name" ;;
esac
# Everything below ends up in /etc/default/tc-control and tc-control's
# command line, so only plain values are accepted.
for p in "$port" "${public_port:-1}"; do
	case $p in
	'' | *[!0-9]*) die "\"$p\" isn't a port number" ;;
	esac
	[ "$p" -ge 1 ] && [ "$p" -le 65535 ] || die "\"$p\" isn't a port number"
done
case $email in
'') ;;
*[!A-Za-z0-9._%+@-]* | *@*@* | @* | *@) die "\"$email\" isn't an email address" ;;
*@*.*) ;;
*) die "\"$email\" isn't an email address" ;;
esac
[ -n "$public_port" ] || public_port=$port
for p in "$port" "$public_port"; do
	case $p in
	'' | *[!0-9]*) die "\"$p\" isn't a port number" ;;
	esac
done

dns=no
case $name in
*.duckdns.org) [ "$nodns" = yes ] || dns=yes ;;
esac

# The DuckDNS token: from duckdns.sh's settings, the environment, or asked.
token=""
if [ "$dns" = yes ]; then
	if [ -r "$DUCKDNS_CONF" ]; then
		token=$(sed -n 's/^TOKEN=//p' "$DUCKDNS_CONF" | tail -n 1)
	fi
	[ -n "$token" ] || token=${DUCKDNS_TOKEN:-}
	if [ -z "$token" ] && [ "$dry" = no ]; then
		[ -t 0 ] || die "no DuckDNS token: install the updater (duckdns.sh install), or set DUCKDNS_TOKEN"
		printf "DuckDNS token (from duckdns.org, top of the page; not shown): "
		stty -echo 2>/dev/null || true
		read -r token || true
		stty echo 2>/dev/null || true
		echo
	fi
	token=$(printf %s "$token" | tr -d '[:space:]')
	case $token in
	*[!0-9a-fA-F-]*) die "that doesn't look like a DuckDNS token (it looks like 1a2b3c4d-1a2b-...)" ;;
	"") [ "$dry" = yes ] || die "no DuckDNS token" ;;
	esac
fi

# The current options, without the ones this script decides.
old=$(sed -n 's/^TC_CONTROL_ARGS=//p' "$SETTINGS" | tail -n 1)
old=${old#\"}
old=${old%\"}
keep="" skip=no was_staging=no old_domain=""
for a in $old; do
	if [ "$skip" != no ]; then
		[ "$skip" = acme-domain ] && old_domain=$a
		skip=no
		continue
	fi
	case $a in
	-acme-staging | --acme-staging | -acme-staging=true) was_staging=yes ;;
	-acme-domain=* | --acme-domain=*) old_domain=${a#*=} ;;
	-acme-domain | --acme-domain) skip=acme-domain ;;
	-tls-self-signed | --tls-self-signed | -tls-self-signed=*) ;;
	-listen | -public-url | -tls-names | -tls-cert | -tls-key | -acme-email | -acme-http-listen | -acme-dns | \
		--listen | --public-url | --tls-names | --tls-cert | --tls-key | --acme-email | --acme-http-listen | --acme-dns) skip=value ;;
	-listen=* | -public-url=* | -tls-names=* | -tls-cert=* | -tls-key=* | -acme-email=* | -acme-http-listen=* | -acme-dns=* | \
		--listen=* | --public-url=* | --tls-names=* | --tls-cert=* | --tls-key=* | --acme-email=* | --acme-http-listen=* | --acme-dns=*) ;;
	*) keep="$keep $a" ;;
	esac
done

url="https://$name"
[ "$public_port" = 443 ] || url="$url:$public_port"

new="-listen :$port -acme-domain $name"
if [ "$dns" = yes ]; then
	new="$new -acme-dns duckdns"
elif [ "$port" != 443 ]; then
	new="$new -acme-http-listen :80"
fi
# tc-control derives the URL from -listen; say it when devices use another port.
[ "$public_port" = "$port" ] || new="$new -public-url $url"
[ -n "$email" ] && new="$new -acme-email $email"
[ "$staging" = yes ] && new="$new -acme-staging"
new="${keep# }${keep:+ }$new"

if [ "$dry" = yes ]; then
	echo "Now:   TC_CONTROL_ARGS=\"$old\""
	echo "Would: TC_CONTROL_ARGS=\"$new\""
	[ "$dns" = yes ] && echo "       TC_DUCKDNS_TOKEN=… (Let's Encrypt checks the name through DuckDNS; no port needs to be open for it)"
	exit 0
fi

addr=$(getent ahostsv4 "$name" 2>/dev/null | awk 'NR==1{print $1}')
[ -n "$addr" ] || die "$name doesn't resolve to an address yet: set up the name first (for DuckDNS: duckdns.sh install)"
echo "$name resolves to $addr here."
if [ "$dns" = yes ]; then
	echo "Let's Encrypt will check the name through DuckDNS: no port needs to be open for that."
	echo "Devices away from home need the router to forward TCP $public_port to this machine's port $port."
else
	echo "Let's Encrypt must reach this machine from the internet on TCP $port$([ "$port" = 443 ] || echo " and 80")."
fi

backup=$SETTINGS.pre-letsencrypt-$(date +%Y%m%d-%H%M%S)
cp -p "$SETTINGS" "$backup"
chmod 600 "$backup"
# The new file is written beside the old one, private from the start (the
# token is a secret: only root, and systemd, which reads it, may read it),
# then moved into place: a new file, so whoever had the old one open never
# sees the token through it.
tmp=$(mktemp "$SETTINGS.XXXXXX")
awk -v line="TC_CONTROL_ARGS=\"$new\"" -v tok="$token" '
	/^TC_CONTROL_ARGS=/ { if (!done) print line; done = 1; next }
	/^TC_DUCKDNS_TOKEN=/ { next }
	{ print }
	END { if (!done) print line; if (tok != "") print "TC_DUCKDNS_TOKEN=" tok }' "$SETTINGS" >"$tmp"
if [ -z "$token" ] && ! grep -q '^TC_DUCKDNS_TOKEN=' "$tmp"; then
	chmod --reference="$SETTINGS" "$tmp" # nothing secret: keep its permissions
fi
mv -f "$tmp" "$SETTINGS"

systemctl stop tc-control
# Certificates are stored by name: a stored test certificate would keep
# being served after leaving the test service, or one for an old name.
clear=no
[ "$was_staging" = yes ] && [ "$staging" = no ] && clear=yes
[ -n "$old_domain" ] && [ "$old_domain" != "$name" ] && clear=yes
if [ -d "$STATE_DIR/acme" ] && [ "$clear" = yes ]; then
	rm -rf "$STATE_DIR/acme"
	echo "Removed the stored certificates (test service, or another name)."
fi
systemctl start tc-control
sleep 2
systemctl is-active --quiet tc-control || {
	journalctl -u tc-control -n 10 --no-pager -o cat >&2
	die "tc-control didn't start (see above). Put the old settings back with: sudo $0 --restore"
}

# Ask this machine directly, so it works even where the router can't loop
# connections to its public address back in. With connection checks, the
# first connection makes tc-control fetch the certificate; with DNS checks
# it fetches it at start, which takes a minute or two.
echo "Getting the certificate (can take up to 5 minutes)..."
k=""
[ "$staging" = yes ] && k=-k
start=$(date +%s)
ok=no out=""
while :; do
	if out=$(curl -sS $k --max-time 90 --resolve "$name:$port:127.0.0.1" "https://$name:$port/key" 2>&1); then
		ok=yes
		break
	fi
	[ $(($(date +%s) - start)) -lt 300 ] || break
	[ "$dns" = yes ] || break # connection checks either work at once or not
	sleep 10
done

if [ "$ok" = yes ]; then
	issuer=$(echo | openssl s_client -connect "127.0.0.1:$port" -servername "$name" 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null || true)
	echo "HTTPS works: $url (${issuer:-certificate in place})"
	if [ "$staging" = yes ]; then
		echo
		echo "That was Let's Encrypt's test service: devices won't trust it. Now run the same without --staging."
	else
		echo
		echo "Move each device to it (same server: they keep their names and addresses, no auth key needed):"
		echo "  sudo tc up --server $url"
		echo "Android: set the server to $url and tap Connect. New devices: see the portal's Auth keys tab."
	fi
else
	echo "$out" >&2
	echo >&2
	journalctl -u tc-control --since "-6min" --no-pager -o cat 2>/dev/null | grep -iE 'acme|certificate|duckdns|verify' | tail -n 5 >&2 || true
	echo >&2
	if [ "$dns" = yes ]; then
		echo "No certificate yet. The lines above are tc-control's reason. Check the DuckDNS token" >&2
		echo "(duckdns.sh status), then run this again." >&2
	else
		echo "No certificate yet. Usually Let's Encrypt couldn't reach this machine: check that $name points at your" >&2
		echo "public address and that the router forwards TCP $port$([ "$port" = 443 ] || echo " and 80") here. Then run this again." >&2
	fi
	echo "To go back to the previous settings: sudo $0 --restore" >&2
	exit 1
fi
