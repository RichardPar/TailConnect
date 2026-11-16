package localapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeBackend struct{ calls []string }

func (f *fakeBackend) Status() Status     { return Status{} }
func (f *fakeBackend) Up(UpRequest) error { f.calls = append(f.calls, "up"); return nil }
func (f *fakeBackend) Down() error        { f.calls = append(f.calls, "down"); return nil }
func (f *fakeBackend) Logout() error      { f.calls = append(f.calls, "logout"); return nil }

func TestAccess(t *testing.T) {
	tests := []struct {
		path, body string
		need       Access // least access that may do it
	}{
		{"/localapi/v1/up", `{}`, AccessUser}, // reconnect
		{"/localapi/v1/up", `{"AuthKey":"tc-auth-x"}`, AccessAdmin},
		{"/localapi/v1/up", `{"ControlURL":"https://example.com"}`, AccessAdmin},
		{"/localapi/v1/up", `{"Hostname":"pc"}`, AccessAdmin},
		{"/localapi/v1/up", `{"ExitNode":""}`, AccessAdmin},
		{"/localapi/v1/down", `{}`, AccessUser},
		{"/localapi/v1/logout", `{}`, AccessAdmin},
	}
	for _, tt := range tests {
		for _, a := range []Access{AccessNone, AccessUser, AccessAdmin} {
			b := &fakeBackend{}
			h := NewServer(b, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
			req := httptest.NewRequest("POST", tt.path, strings.NewReader(tt.body))
			req = req.WithContext(WithAccess(req.Context(), a))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			want := http.StatusForbidden
			if a >= tt.need {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Errorf("%s %s with access %d: HTTP %d, want %d", tt.path, tt.body, a, rec.Code, want)
			}
			if (len(b.calls) > 0) != (want == http.StatusOK) {
				t.Errorf("%s %s with access %d: backend calls %v", tt.path, tt.body, a, b.calls)
			}
		}
	}
	// Without an access value (no peer credentials), only status works.
	h := NewServer(&fakeBackend{}, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
	for _, p := range []string{"/localapi/v1/down", "/localapi/v1/up"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", p, strings.NewReader(`{}`)))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s without access: HTTP %d", p, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/localapi/v1/status", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status without access: HTTP %d", rec.Code)
	}
}
