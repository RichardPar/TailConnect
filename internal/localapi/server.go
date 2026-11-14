package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Server struct {
	b   Backend
	log *slog.Logger
}

func NewServer(b Backend, log *slog.Logger) *Server { return &Server{b: b, log: log} }

type uidCtx struct{}

// Handler returns the API handler. Requests must carry the caller's UID in
// their context (see Serve); without it, mutating calls are refused.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /localapi/v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.b.Status())
	})
	mux.HandleFunc("POST /localapi/v1/up", s.privileged(func(w http.ResponseWriter, r *http.Request) {
		var req UpRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad request: "+err.Error())
			return
		}
		s.result(w, s.b.Up(req))
	}))
	mux.HandleFunc("POST /localapi/v1/down", s.privileged(func(w http.ResponseWriter, r *http.Request) {
		s.result(w, s.b.Down())
	}))
	mux.HandleFunc("POST /localapi/v1/logout", s.privileged(func(w http.ResponseWriter, r *http.Request) {
		s.result(w, s.b.Logout())
	}))
	return mux
}

func (s *Server) result(w http.ResponseWriter, err error) {
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.b.Status())
}

func (s *Server) privileged(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, ok := r.Context().Value(uidCtx{}).(int)
		if !ok || (uid != 0 && uid != os.Geteuid()) {
			writeError(w, http.StatusForbidden, "permission denied: run as root (e.g. sudo tc ...)")
			return
		}
		h(w, r)
	}
}

// Listen creates the Unix socket at path (replacing a stale one). The socket
// is world-accessible; privilege is checked per request via peer credentials.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, fmt.Errorf("another tcd is already listening on %s", path)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve runs the API on ln until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if uid, err := peerUID(c); err == nil {
				return context.WithValue(ctx, uidCtx{}, uid)
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
