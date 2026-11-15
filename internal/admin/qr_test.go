package admin

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"tailconnect/internal/db"
)

func TestJoinURL(t *testing.T) {
	u, err := url.Parse(JoinURL("http://192.168.1.10:7740", "tc-auth-abc"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "tailconnect" || u.Host != "join" || u.Query().Get("server") != "http://192.168.1.10:7740" || u.Query().Get("key") != "tc-auth-abc" {
		t.Fatalf("join URL: %s", u)
	}
	svg, err := qrSVG(u.String())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		XMLName xml.Name `xml:"svg"`
		ViewBox string   `xml:"viewBox,attr"`
	}
	if err := xml.Unmarshal([]byte(svg), &doc); err != nil {
		t.Fatalf("not well-formed SVG: %v", err)
	}
	// A URL this long needs QR version 4 or more (33+ modules) plus the quiet zone.
	var n int
	if _, err := fmtSscan(doc.ViewBox, &n); err != nil || n < 33+8 || !strings.Contains(svg, `fill="#fff"`) {
		t.Fatalf("viewBox %q", doc.ViewBox)
	}
}

// Creating a key returns its join link and QR code.
func TestKeyQR(t *testing.T) {
	f := newFx(t)
	f.srv.info.ControlURL = "https://vpn.example.com"
	alice := f.account("alice", db.RoleTenant)
	code, m, _ := f.do(alice, "POST", "/api/v1/keys", map[string]any{"ttl": "24h"}, nil)
	if code != 201 {
		t.Fatalf("create key: %d %v", code, m)
	}
	key, _ := m["key"].(string)
	join, _ := m["joinURL"].(string)
	svg, _ := m["qrSvg"].(string)
	if !strings.HasPrefix(join, "tailconnect://join?") || !strings.Contains(join, url.QueryEscape(key)) || !strings.Contains(join, url.QueryEscape("https://vpn.example.com")) {
		t.Fatalf("joinURL %q for key %q", join, key)
	}
	if !strings.HasPrefix(svg, "<svg") {
		t.Fatalf("qrSvg: %.60q", svg)
	}
}

// fmtSscan reads the size from "0 0 N N".
func fmtSscan(viewBox string, n *int) (int, error) {
	var a, b, c int
	return fmt.Sscan(viewBox, &a, &b, n, &c)
}
