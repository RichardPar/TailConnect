#!/bin/sh
# Switch tc-control to HTTPS with a free Let's Encrypt certificate for a DNS
# name (e.g. a DuckDNS name). tc-control gets and renews the certificate
# itself; this script only changes its settings, restarts it and checks.
#
#   sudo packaging/linux/letsencrypt.sh NAME [options]
#   sudo packaging/linux/letsencrypt.sh --restore     # put the previous settings back
#
#   --port N      HTTPS port devices connect to (default 443). With another
#                 port, TCP 80 must reach this machine too, for Let's Encrypt.
#   --email ADDR  contact address for Let's Encrypt (optional)
#   --staging     use Let's Encrypt's test service first (untrusted
#                 certificates, generous limits); run again without it after
#   --dry-run     show the new settings without changing anything
#
# Before running it: NAME must point at this network's public address, and
# the router must forward TCP 443 (or --port, and 80) and UDP 3478 here.
# Only the server needs the certificate: devices need nothing but the URL.
# See docs/duckdns.md and docs/lets-encrypt.md.
set -eu

DEFAULTS=${DEFAULTS:-/etc/default}
SETTINGS=$DEFAULTS/tc-control
STATE_DIR=${STATE_DIR:-/var/lib/tc-control}

die() { echo "letsencrypt.sh: $*" >&2; exit 1; }
usage() { sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

name="" port=443 email="" staging=no dry=no restore=no
while [ $# -gt 0 ]; do
	case $1 in
	--port) [ $# -ge 2 ] || usage; port=$2; shift ;;
	--port=*) port=${1#*=} ;;
	--email) [ $# -ge 2 ] || usage; email=$2; shift ;;
	--email=*) email=${1#*=} ;;
	--staging) staging=yes ;;
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
	cp "$last" "$SETTINGS"
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
case $port in
'' | *[!0-9]*) die "--port: \"$port\" isn't a port number" ;;
esac

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
	-listen | -public-url | -tls-names | -tls-cert | -tls-key | -acme-email | -acme-http-listen | \
		--listen | --public-url | --tls-names | --tls-cert | --tls-key | --acme-email | --acme-http-listen) skip=value ;;
	-listen=* | -public-url=* | -tls-names=* | -tls-cert=* | -tls-key=* | -acme-email=* | -acme-http-listen=* | \
		--listen=* | --public-url=* | --tls-names=* | --tls-cert=* | --tls-key=* | --acme-email=* | --acme-http-listen=*) ;;
	*) keep="$keep $a" ;;
	esac
done

new="-listen :$port -acme-domain $name"
[ "$port" = 443 ] || new="$new -acme-http-listen :80"
[ -n "$email" ] && new="$new -acme-email $email"
[ "$staging" = yes ] && new="$new -acme-staging"
new="${keep# }${keep:+ }$new"

url="https://$name"
[ "$port" = 443 ] || url="$url:$port"

if [ "$dry" = yes ]; then
	echo "Now:   TC_CONTROL_ARGS=\"$old\""
	echo "Would: TC_CONTROL_ARGS=\"$new\""
	exit 0
fi

addr=$(getent ahostsv4 "$name" 2>/dev/null | awk 'NR==1{print $1}')
[ -n "$addr" ] || die "$name doesn't resolve to an address yet: set up the name first (for DuckDNS: duckdns.sh install)"
echo "$name resolves to $addr here. Let's Encrypt must reach it from the internet on TCP $port$([ "$port" = 443 ] || echo " and 80")."

backup=$SETTINGS.pre-letsencrypt-$(date +%Y%m%d-%H%M%S)
cp "$SETTINGS" "$backup"
tmp=$(mktemp)
awk -v line="TC_CONTROL_ARGS=\"$new\"" '/^TC_CONTROL_ARGS=/ { if (!done) print line; done = 1; next } { print } END { if (!done) print line }' "$SETTINGS" >"$tmp"
cat "$tmp" >"$SETTINGS"
rm -f "$tmp"

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

# The first HTTPS connection makes tc-control fetch the certificate. Ask
# this machine directly, so it works even where the router can't loop
# connections to its public address back in.
echo "Getting the certificate (can take up to a minute)..."
k=""
[ "$staging" = yes ] && k=-k
if out=$(curl -sS $k --max-time 90 --resolve "$name:$port:127.0.0.1" "https://$name:$port/key" 2>&1); then
	issuer=$(echo | openssl s_client -connect "127.0.0.1:$port" -servername "$name" 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null || true)
	echo "HTTPS works: $url (${issuer:-certificate in place})"
	if [ "$staging" = yes ]; then
		echo
		echo "That was Let's Encrypt's test service: devices won't trust it. Now run without --staging:"
		echo "  sudo $0 $name$([ "$port" = 443 ] || echo " --port $port")${email:+ --email $email}"
	else
		echo
		echo "Move each device to it (same server: they keep their names and addresses, no auth key needed):"
		echo "  sudo tc up --server $url"
		echo "Android: set the server to $url and tap Connect. New devices: see the portal's Auth keys tab."
	fi
else
	echo "$out" >&2
	echo >&2
	journalctl -u tc-control --since "-3min" --no-pager -o cat 2>/dev/null | grep -iE 'acme|certificate|verify' | tail -n 5 >&2 || true
	echo >&2
	echo "No certificate yet. Usually Let's Encrypt couldn't reach this machine: check that $name points at your" >&2
	echo "public address and that the router forwards TCP $port$([ "$port" = 443 ] || echo " and 80") here. Then run this again." >&2
	echo "To go back to the previous settings: sudo $0 --restore" >&2
	exit 1
fi
