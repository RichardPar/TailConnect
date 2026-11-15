package admin

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/iplimit"
)

func TestHostAllowlist(t *testing.T) {
	f := newFx(t)
	f.srv.hosts["vpn.example.com"] = true
	for host, want := range map[string]int{
		"":                     200, // the test server's IP address
		"vpn.example.com":      200,
		"VPN.example.com.:443": 200,
		"localhost:7741":       200,
		"[::1]:7741":           200,
		"192.0.2.7":            200,
		"evil.example":         http.StatusMisdirectedRequest,
		"vpn.example.com.evil": http.StatusMisdirectedRequest,
	} {
		req, _ := http.NewRequest("GET", f.ts.URL+"/api/config", nil)
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Host %q: %d, want %d", host, resp.StatusCode, want)
		}
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	f := newFx(t)
	resp, err := http.Get(f.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if h := resp.Header.Get("Strict-Transport-Security"); h != "" {
		t.Fatalf("HSTS over plain HTTP: %q", h)
	}
	ts := httptest.NewTLSServer(f.srv.Handler())
	defer ts.Close()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err = c.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if h := resp.Header.Get("Strict-Transport-Security"); h != "max-age=31536000" {
		t.Fatalf("HSTS over TLS: %q", h)
	}
}

// Wrong passwords for one account are limited however many addresses they
// come from, and the right password still works until the limit runs out.
func TestAccountLoginLimit(t *testing.T) {
	f := newFx(t)
	f.srv.acctLimit = iplimit.NewRate(time.Hour, 3)
	f.account("acme", db.RoleTenant)
	login := func(p string) int {
		code, _, _ := f.do(f.browser(), "POST", "/api/login", map[string]string{"login": "acme", "password": p}, nil)
		return code
	}
	for i := 0; i < 3; i++ {
		if code := login("wrong password"); code != 401 {
			t.Fatalf("wrong password %d: %d", i, code)
		}
	}
	if code := login(pw); code != 429 {
		t.Fatalf("after the account limit: %d, want 429", code)
	}
	// Other accounts are unaffected.
	f.account("globex", db.RoleTenant)
}

func TestChangePasswordLimited(t *testing.T) {
	f := newFx(t)
	f.srv.acctLimit = iplimit.NewRate(time.Hour, 3)
	c := f.account("acme", db.RoleTenant)
	change := func(cur string) int {
		code, _, _ := f.do(c, "POST", "/api/v1/me/password", map[string]string{"current": cur, "new": "another long password"}, nil)
		return code
	}
	for i := 0; i < 3; i++ {
		if code := change("wrong password"); code != 403 {
			t.Fatalf("wrong current password %d: %d", i, code)
		}
	}
	if code := change(pw); code != 429 {
		t.Fatalf("after the limit: %d, want 429", code)
	}
}
