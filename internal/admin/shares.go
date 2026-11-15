package admin

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"tailconnect/internal/db"
)

// MaxShareLinkTTL caps how long an unredeemed share link stays valid.
const MaxShareLinkTTL = 30 * 24 * time.Hour

type apiShare struct {
	ID         int64      `json:"id"`
	NodeID     int64      `json:"nodeId"`
	Machine    string     `json:"machine"`
	FQDN       string     `json:"fqdn"`
	Owner      string     `json:"owner"`
	Recipient  string     `json:"recipient,omitempty"` // "" for an unredeemed link
	Status     string     `json:"status"`
	InEffect   bool       `json:"inEffect"`
	Link       bool       `json:"link"`
	LinkPrefix string     `json:"linkPrefix,omitempty"`
	Created    time.Time  `json:"created"`
	AcceptedAt *time.Time `json:"acceptedAt,omitempty"`
	Expires    *time.Time `json:"expires,omitempty"`
}

func (s *Server) toAPIShare(sh db.Share) apiShare {
	out := apiShare{
		ID: sh.ID, NodeID: sh.NodeID, Machine: sh.NodeName,
		FQDN:  sh.NodeName + "." + db.TenantDomain(sh.OwnerName, sh.OwnerDomain, s.info.BaseDomain),
		Owner: sh.OwnerName, Recipient: sh.RecipientName, Status: sh.Status, InEffect: sh.InEffect(),
		Link: sh.Link, LinkPrefix: sh.LinkPrefix, Created: sh.CreatedAt,
	}
	if !sh.AcceptedAt.IsZero() {
		t := sh.AcceptedAt
		out.AcceptedAt = &t
	}
	if !sh.ExpiresAt.IsZero() && sh.RecipientID == 0 {
		t := sh.ExpiresAt
		out.Expires = &t
	}
	return out
}

// listShares returns the principal's shares: those of its machines
// (outgoing) and those offered to it (incoming). The admin token sees every
// share as outgoing.
func (s *Server) listShares(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var f db.ShareFilter
	if p.user != nil {
		f.OwnerID, f.RecipientID = p.user.ID, p.user.ID
	}
	list, err := s.db.ListShares(r.Context(), f)
	if err != nil {
		s.internal(w, "list shares", err)
		return
	}
	out := struct {
		Outgoing []apiShare `json:"outgoing"`
		Incoming []apiShare `json:"incoming"`
	}{Outgoing: []apiShare{}, Incoming: []apiShare{}}
	now := s.now()
	for _, sh := range list {
		if p.user != nil && sh.RecipientID == p.user.ID {
			out.Incoming = append(out.Incoming, s.toAPIShare(sh))
			continue
		}
		if sh.RecipientID == 0 && !sh.ExpiresAt.IsZero() && now.After(sh.ExpiresAt) {
			continue // expired, unredeemed link: nothing to show
		}
		out.Outgoing = append(out.Outgoing, s.toAPIShare(sh))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) shareNode(w http.ResponseWriter, r *http.Request) {
	n, ok := s.ownNode(w, r)
	if !ok {
		return
	}
	var req struct{ Recipient string }
	if !decode(w, r, &req) {
		return
	}
	sh, err := s.db.ShareWith(r.Context(), n.ID, strings.ToLower(strings.TrimSpace(req.Recipient)))
	if s.dbError(w, "share", err) {
		return
	}
	s.log.Info("share offered", "machine", n.GivenName, "owner", n.UserName, "recipient", sh.RecipientName, "by", principalFrom(r.Context()).name())
	writeJSON(w, http.StatusCreated, s.toAPIShare(sh))
}

func (s *Server) createShareLink(w http.ResponseWriter, r *http.Request) {
	n, ok := s.ownNode(w, r)
	if !ok {
		return
	}
	var req struct{ TTL string }
	if !decode(w, r, &req) {
		return
	}
	ttl, err := time.ParseDuration(req.TTL)
	if err != nil || ttl <= 0 || ttl > MaxShareLinkTTL {
		writeError(w, http.StatusBadRequest, "ttl must be a duration between 1s and 720h (30 days)")
		return
	}
	code, sh, err := s.db.CreateShareLink(r.Context(), n.ID, ttl)
	if s.dbError(w, "share link", err) {
		return
	}
	s.log.Info("share link created", "machine", n.GivenName, "owner", n.UserName, "by", principalFrom(r.Context()).name())
	writeJSON(w, http.StatusCreated, map[string]any{"code": code, "share": s.toAPIShare(sh)})
}

func (s *Server) acceptShare(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.user == nil {
		writeError(w, http.StatusBadRequest, "sign in with an account to accept shares")
		return
	}
	id, ok := pathID(w, r)
	if !ok || s.dbError(w, "accept share", s.db.AcceptShare(r.Context(), id, p.user.ID)) {
		return
	}
	sh, err := s.db.GetShare(r.Context(), id)
	if s.dbError(w, "accept share", err) {
		return
	}
	s.log.Info("share accepted", "machine", sh.NodeName, "owner", sh.OwnerName, "recipient", p.user.Name)
	writeJSON(w, http.StatusOK, s.toAPIShare(sh))
}

func (s *Server) redeemShareLink(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.user == nil {
		writeError(w, http.StatusBadRequest, "sign in with an account to redeem a share link")
		return
	}
	var req struct{ Code string }
	if !decode(w, r, &req) {
		return
	}
	sh, err := s.db.RedeemShareLink(r.Context(), req.Code, p.user.ID)
	if errors.Is(err, db.ErrInvalidShareLink) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.dbError(w, "redeem share link", err) {
		return
	}
	s.log.Info("share link redeemed", "machine", sh.NodeName, "owner", sh.OwnerName, "recipient", p.user.Name)
	writeJSON(w, http.StatusOK, s.toAPIShare(sh))
}

// deleteShare revokes (owner), declines or leaves (recipient) a share;
// operators may delete any.
func (s *Server) deleteShare(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	actor := p.scope()
	if !p.operator() {
		actor = p.user.ID
	}
	if s.dbError(w, "delete share", s.db.DeleteShare(r.Context(), id, actor)) {
		return
	}
	s.log.Info("share removed", "id", id, "by", p.name())
	w.WriteHeader(http.StatusNoContent)
}
