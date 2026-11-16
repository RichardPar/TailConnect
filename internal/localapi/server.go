package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

type Server struct {
	b   Backend
	log *slog.Logger
}

func NewServer(b Backend, log *slog.Logger) *Server { return &Server{b: b, log: log} }

// Access is what a caller may do.
type Access int

const (
	AccessNone  Access = iota // read status only
	AccessUser                // also connect (a plain `tc up`) and disconnect (Windows: any signed-in user)
	AccessAdmin               // everything: log in, change server or settings, log out
)

type accessCtx struct{}

// WithAccess returns ctx for a caller with access a (see Serve).
func WithAccess(ctx context.Context, a Access) context.Context {
	return context.WithValue(ctx, accessCtx{}, a)
}

// Handler returns the API handler. Requests must carry the caller's access
// in their context (WithAccess; Serve does this); without it, only status is
// served.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /localapi/v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.b.Status())
	})
	mux.HandleFunc("POST /localapi/v1/up", func(w http.ResponseWriter, r *http.Request) {
		var req UpRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request: "+err.Error())
			return
		}
		need := AccessAdmin
		if req.reconnect() {
			need = AccessUser
		}
		if !allowed(w, r, need) {
			return
		}
		s.result(w, s.b.Up(req))
	})
	mux.HandleFunc("POST /localapi/v1/down", func(w http.ResponseWriter, r *http.Request) {
		if allowed(w, r, AccessUser) {
			s.result(w, s.b.Down())
		}
	})
	mux.HandleFunc("POST /localapi/v1/logout", func(w http.ResponseWriter, r *http.Request) {
		if allowed(w, r, AccessAdmin) {
			s.result(w, s.b.Logout())
		}
	})
	return mux
}

// reconnect reports whether req only brings the tunnel back up, changing
// nothing.
func (req UpRequest) reconnect() bool {
	return req.ControlURL == "" && req.AuthKey == "" && req.Hostname == "" && req.ServerKey.IsZero() &&
		req.TLSFingerprint == "" && req.ExitNode == nil
}

// allowed checks the caller's access, answering 403 if it falls short.
func allowed(w http.ResponseWriter, r *http.Request, need Access) bool {
	if a, _ := r.Context().Value(accessCtx{}).(Access); a >= need {
		return true
	}
	writeError(w, http.StatusForbidden, "permission denied: "+ElevateHint)
	return false
}

func (s *Server) result(w http.ResponseWriter, err error) {
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.b.Status())
}

// Serve runs the API on ln until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if a, err := peerAccess(c); err == nil {
				return WithAccess(ctx, a)
			} else {
				s.log.Warn("localapi: cannot read peer credentials", "err", err)
			}
			return ctx
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
