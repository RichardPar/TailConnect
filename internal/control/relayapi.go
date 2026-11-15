package control

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
)

// maxRelayPairs bounds one RelayAllowedRequest.
const maxRelayPairs = 1024

// relayWatchTimeout is how long a watch waits for a change before
// answering anyway (below common proxy idle timeouts).
var relayWatchTimeout = 25 * time.Second

// AuthorizeRelayClient decides whether machine nk may connect to a relay:
// it must be registered, approved, unexpired and in an active account.
func (s *Server) AuthorizeRelayClient(ctx context.Context, nk key.NodePublic) error {
	n, err := s.db.GetNodeByNodeKey(ctx, nk.String())
	if errors.Is(err, db.ErrNotFound) {
		return errors.New("node not registered")
	}
	if err != nil {
		return err
	}
	if notice := cutOffNotice(n, time.Now()); notice != "" {
		return errors.New("machine is cut off: " + notice)
	}
	return nil
}

// generation is the relay policy's version: it increases whenever the
// policy is rebuilt (a database change, or a key expiring).
func (s *Server) generation() int64 {
	s.policyMu.RLock()
	defer s.policyMu.RUnlock()
	return s.policyEpoch
}

func (s *Server) relayAPI(next func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeError(w, http.StatusUnauthorized, "relay token required")
			return
		}
		_, err := s.db.CheckRelayToken(r.Context(), tok)
		if errors.Is(err, db.ErrNotFound) {
			s.log.Info("relay API: unknown relay token", "remote", r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "unknown relay token")
			return
		}
		if err != nil {
			s.internalError(w, "relay API", err)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleRelayAuthorize(w http.ResponseWriter, r *http.Request) {
	var req protocol.RelayAuthorizeRequest
	if !decode(w, r, &req) {
		return
	}
	resp := protocol.RelayAuthorizeResponse{Allowed: true, Generation: s.generation()}
	if err := s.AuthorizeRelayClient(r.Context(), req.Node); err != nil {
		resp.Allowed, resp.Reason = false, err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRelayAllowed(w http.ResponseWriter, r *http.Request) {
	var req protocol.RelayAllowedRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Pairs) > maxRelayPairs {
		writeError(w, http.StatusBadRequest, "too many pairs")
		return
	}
	// Generation first: the answers are at least this fresh.
	resp := protocol.RelayAllowedResponse{Generation: s.generation(), Allowed: make([]bool, len(req.Pairs))}
	for i, p := range req.Pairs {
		resp.Allowed[i] = s.RelayAllowed(p[0], p[1])
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRelayWatch(w http.ResponseWriter, r *http.Request) {
	since, err := strconv.ParseInt(r.URL.Query().Get("generation"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "generation required")
		return
	}
	changed := s.bus.wait()
	if g := s.generation(); g != since {
		writeJSON(w, http.StatusOK, protocol.RelayWatchResponse{Generation: g})
		return
	}
	t := time.NewTimer(relayWatchTimeout)
	defer t.Stop()
	select {
	case <-changed:
	case <-t.C:
	case <-r.Context().Done():
		return
	}
	writeJSON(w, http.StatusOK, protocol.RelayWatchResponse{Generation: s.generation()})
}
