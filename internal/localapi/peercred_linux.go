//go:build linux

package localapi

import (
	"errors"
	"net"
	"os"
	"os/user"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

func peerUID(c net.Conn) (int, error) {
	cred, err := peerCred(c)
	if err != nil {
		return -1, err
	}
	return int(cred.Uid), nil
}

// peerCred returns the connecting process's credentials (SO_PEERCRED).
func peerCred(c net.Conn) (*unix.Ucred, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, cerr
}

// peerAccess gives root and the daemon's own user full access, members of
// OperatorGroup user access (connect and disconnect), others none.
func peerAccess(c net.Conn) (Access, error) {
	cred, err := peerCred(c)
	if err != nil {
		return AccessNone, err
	}
	uid := int(cred.Uid)
	if uid == 0 || uid == os.Geteuid() {
		return AccessAdmin, nil
	}
	if inGroup(OperatorGroup, uid, int(cred.Gid)) {
		return AccessUser, nil
	}
	return AccessNone, nil
}

// inGroup reports whether the user (with primary group gid) is in the
// named group, read from /etc/group now, so adding someone takes effect
// without logging in again.
func inGroup(name string, uid, gid int) bool {
	g, err := user.LookupGroup(name)
	if err != nil {
		return false
	}
	if g.Gid == strconv.Itoa(gid) {
		return true
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return false
	}
	ids, err := u.GroupIds()
	return err == nil && slices.Contains(ids, g.Gid)
}
