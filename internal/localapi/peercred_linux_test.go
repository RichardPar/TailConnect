package localapi

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPeerAccessOwnUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := net.Dial("unix", path); err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The test process is the daemon's own user here.
	if a, err := peerAccess(c); err != nil || a != AccessAdmin {
		t.Fatalf("own uid: %v %v", a, err)
	}
}

func TestInGroup(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		t.Skip(err)
	}
	if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil && !inGroup(g.Name, uid, gid) {
		t.Errorf("not in own primary group %s", g.Name)
	}
	ids, _ := u.GroupIds()
	for _, id := range ids {
		if id == strconv.Itoa(gid) {
			continue
		}
		g, err := user.LookupGroupId(id)
		if err != nil {
			continue
		}
		if !inGroup(g.Name, uid, -1) {
			t.Errorf("not in supplementary group %s", g.Name)
		}
		t.Logf("supplementary group %s ok", g.Name)
		break
	}
	if inGroup("no-such-group-tc", uid, gid) {
		t.Error("in a group that doesn't exist")
	}
	if inGroup(OperatorGroup, 65534, 65534) {
		t.Error("nobody is in the tailconnect group")
	}
}
