package admin

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// The portal answers only to names it knows. A web page can point its own
// name at this server (DNS rebinding) and have a visitor's browser send it
// requests; those carry the page's name in Host, so they are refused. IP
// addresses are always allowed: a page can't rebind those.

// normalHost lowercases a Host header value and strips its port, brackets
// and trailing dot.
func normalHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), ".")
}

func (s *Server) hostAllowed(h string) bool {
	h = normalHost(h)
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return s.hosts[h]
}

func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			s.log.Warn("web portal: request for an unknown host name refused; add it with -admin-hosts if it is yours",
				"host", r.Host, "remote", r.RemoteAddr)
			http.Error(w, "unknown host name "+normalHost(r.Host)+": the operator can allow it with tc-control serve -admin-hosts",
				http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}
