package localapi

import (
	"context"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// DefaultSocket is the named pipe tcd listens on by default.
const DefaultSocket = `\\.\pipe\tailconnect`

// ElevateHint says how to run a privileged command.
const ElevateHint = "run tc from an Administrator command prompt"

// SudoPrefix goes before example privileged commands.
const SudoPrefix = ""

// pipeSDDL lets SYSTEM and Administrators do anything with the pipe and any
// signed-in user connect to it. Privilege is checked per request.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"

type handler interface{ Handle() windows.Handle }

func dial(ctx context.Context, path string) (net.Conn, error) {
	c, err := namedpipe.DialContext(ctx, path)
	if err != nil {
		return nil, err
	}
	// Anyone can create a pipe with this name while tcd is not running. Only
	// talk to one created by SYSTEM or an Administrator, so `tc up` cannot be
	// tricked into handing an auth key to another user's program.
	if path == DefaultSocket {
		if err := checkPipeOwner(c); err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

func checkPipeOwner(c net.Conn) error {
	h, ok := c.(handler)
	if !ok {
		return errors.New("not a named pipe")
	}
	sd, err := windows.GetSecurityInfo(h.Handle(), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("pipe owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("pipe owner: %w", err)
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	return fmt.Errorf("refusing to use %s: it was not created by the TailConnect service (owner %s)", DefaultSocket, owner)
}

// Listen creates the named pipe at path. It fails if the pipe already exists
// (another tcd, or another program holding the name).
func Listen(path string) (net.Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return nil, err
	}
	ln, err := (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(path)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
		return nil, fmt.Errorf("%s is already in use (is tcd already running?): %w", path, err)
	}
	return ln, err
}

// peerPrivileged reports whether the process at the other end of the pipe
// runs as SYSTEM, has the Administrators group enabled (an Administrator
// prompt; not a UAC-filtered or "basic user" token, where the group is
// deny-only), or runs as the daemon's own user.
func peerPrivileged(c net.Conn) (bool, error) {
	h, ok := c.(handler)
	if !ok {
		return false, errors.New("not a named pipe")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h.Handle(), &pid); err != nil {
		return false, err
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return false, err
	}
	defer tok.Close()
	peer, err := tok.GetTokenUser()
	if err != nil {
		return false, err
	}
	if peer.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return true, nil
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	if windows.EqualSid(peer.User.Sid, self.User.Sid) {
		return true, nil
	}
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return false, err
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return g.Attributes&windows.SE_GROUP_ENABLED != 0 && g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0, nil
		}
	}
	return false, nil
}
