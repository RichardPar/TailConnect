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

type privCtx struct{}

// Handler returns the API handler. Requests must say in their context whether
// the caller is privileged (see Serve); without it, mutating calls are refused.
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
		if ok, _ := r.Context().Value(privCtx{}).(bool); !ok {
			writeError(w, http.StatusForbidden, "permission denied: "+ElevateHint)
			return
		}
		h(w, r)
	}
}

// Serve runs the API on ln until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if priv, err := peerPrivileged(c); err == nil {
				return context.WithValue(ctx, privCtx{}, priv)
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
