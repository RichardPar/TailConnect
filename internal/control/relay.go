package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"tailconnect/internal/db"
	"tailconnect/internal/key"
	"tailconnect/internal/protocol"
	"tailconnect/internal/relay"
)

const settingRelayKey = "relay.key"

// EmbeddedRelayPath is where tc-control serves its built-in relay.
const EmbeddedRelayPath = "/relay"

// EmbeddedRelayMap advertises the built-in relay as region 1. Its URL is
// relative, so clients resolve it against the control URL they already use.
// stunPort > 0 advertises a STUN server on the control host at that port.
func EmbeddedRelayMap(stunPort int) protocol.RelayMap {
	return protocol.RelayMap{Regions: []protocol.RelayRegion{{
		ID: 1, Code: "control", Name: "tc-control (embedded)",
		Nodes: []protocol.RelayNode{{Name: "1a", URL: EmbeddedRelayPath, STUNPort: stunPort}},
	}}}
}

// NewEmbeddedRelay returns a relay server whose key is persisted in the
// database and which only serves nodes registered with this control server.
func NewEmbeddedRelay(ctx context.Context, d *db.DB, log *slog.Logger) (*relay.Server, error) {
	fresh, _ := key.NewPrivate[key.RelayKind]().MarshalText()
	stored, err := d.SetSettingIfAbsent(ctx, settingRelayKey, string(fresh))
	if err != nil {
		return nil, fmt.Errorf("relay key: %w", err)
	}
	rk, err := key.ParsePrivate[key.RelayKind](stored)
	if err != nil {
		return nil, fmt.Errorf("relay key: %w", err)
	}
	authorize := func(ctx context.Context, nk key.NodePublic) error {
		n, err := d.GetNodeByNodeKey(ctx, nk.String())
		if errors.Is(err, db.ErrNotFound) {
			return errors.New("node not registered")
		}
		if err == nil && n.UserStatus != db.StatusActive {
			return errors.New("account not active")
		}
		return err
	}
	return relay.NewServer(rk, authorize, log), nil
}
