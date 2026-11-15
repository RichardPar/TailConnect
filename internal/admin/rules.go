package admin

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"tailconnect/internal/acl"
	"tailconnect/internal/db"
)

type apiRule struct {
	ID      int64     `json:"id"`
	User    string    `json:"user"`
	Src     string    `json:"src"`
	Dst     string    `json:"dst"`
	Ports   string    `json:"ports"`
	Created time.Time `json:"created"`
}

func toAPIRule(r db.Rule) apiRule {
	return apiRule{ID: r.ID, User: r.UserName, Src: r.Src, Dst: r.Dst, Ports: r.Ports, Created: r.CreatedAt}
}

func (s *Server) setNodeTags(w http.ResponseWriter, r *http.Request) {
	n, ok := s.ownNode(w, r)
	if !ok {
		return
	}
	var req struct{ Tags []string }
	if !decode(w, r, &req) {
		return
	}
	tags := []string{}
	for _, t := range req.Tags {
		t = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(t, "tag:")))
		if t == "" {
			continue
		}
		if !acl.ValidTag(t) {
			writeError(w, http.StatusBadRequest, "bad tag "+t+": use lowercase letters, digits and '-'")
			return
		}
		tags = append(tags, t)
	}
	slices.Sort(tags)
	tags = slices.Compact(tags)
	if s.dbError(w, "set tags", s.db.SetNodeTags(r.Context(), n.ID, tags)) {
		return
	}
	s.log.Info("machine tags set", "node", n.GivenName, "user", n.UserName, "tags", tags, "by", principalFrom(r.Context()).name())
	s.writeNode(w, r, n.ID)
}

// ruleAccount is the account a rules request is about: a tenant's own, or
// for operators the ?user= / body account (empty = all, for listing).
func (s *Server) ruleAccount(w http.ResponseWriter, r *http.Request, name string) (db.User, bool) {
	p := principalFrom(r.Context())
	if !p.operator() {
		return *p.user, true
	}
	if name == "" {
		if p.user != nil {
			return *p.user, true
		}
		return db.User{}, true // admin token, listing everything
	}
	u, err := s.db.GetUser(r.Context(), name)
	if s.dbError(w, "rules", err) {
		return db.User{}, false
	}
	return u, true
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	u, ok := s.ruleAccount(w, r, r.URL.Query().Get("user"))
	if !ok {
		return
	}
	rules, err := s.db.ListRules(r.Context(), u.ID)
	if err != nil {
		s.internal(w, "list rules", err)
		return
	}
	out := make([]apiRule, 0, len(rules))
	for _, ru := range rules {
		out = append(out, toAPIRule(ru))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) addRule(w http.ResponseWriter, r *http.Request) {
	var req struct{ Src, Dst, Ports, User string }
	if !decode(w, r, &req) {
		return
	}
	u, ok := s.ruleAccount(w, r, req.User)
	if !ok {
		return
	}
	if u.ID == 0 {
		writeError(w, http.StatusBadRequest, "say which account the rule is for (user)")
		return
	}
	src, dst := strings.ToLower(strings.TrimSpace(req.Src)), strings.ToLower(strings.TrimSpace(req.Dst))
	if err := acl.CheckSelector(src); err != nil {
		writeError(w, http.StatusBadRequest, "from: "+err.Error())
		return
	}
	if err := acl.CheckSelector(dst); err != nil {
		writeError(w, http.StatusBadRequest, "to: "+err.Error())
		return
	}
	access, err := acl.ParsePorts(req.Ports)
	if err != nil {
		writeError(w, http.StatusBadRequest, "ports: "+err.Error())
		return
	}
	rule, err := s.db.AddRule(r.Context(), u.ID, src, dst, acl.FormatPorts(access))
	if s.dbError(w, "add rule", err) {
		return
	}
	rule.UserName = u.Name
	s.log.Info("access rule added", "user", u.Name, "src", src, "dst", dst, "ports", rule.Ports, "by", principalFrom(r.Context()).name())
	writeJSON(w, http.StatusCreated, toAPIRule(rule))
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok || s.dbError(w, "delete rule", s.db.DeleteRule(r.Context(), id, principalFrom(r.Context()).scope())) {
		return
	}
	s.log.Info("access rule deleted", "id", id, "by", principalFrom(r.Context()).name())
	w.WriteHeader(http.StatusNoContent)
}
