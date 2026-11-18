package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"tailconnect/internal/db"
	"tailconnect/internal/key"
)

// benchServer is a control server with `tenants` accounts of `perTenant`
// machines each, and (optionally) every account's first machine shared with
// the next account.
type benchServer struct {
	srv   *Server
	db    *db.DB
	ids   []int64
	keys  []key.NodePublic
	owner []int
}

func newBenchServer(b testing.TB, tenants, perTenant int, share bool) *benchServer {
	b.Helper()
	d, err := db.Open(filepath.Join(b.TempDir(), "c.db"))
	if err != nil {
		b.Fatal(err)
	}
	s, err := New(context.Background(), d, Config{BaseDomain: "tc.internal", PollInterval: time.Hour}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close(); d.Close() })
	bs := &benchServer{srv: s, db: d}
	ctx := context.Background()
	for t := 0; t < tenants; t++ {
		u, err := d.CreateUser(ctx, fmt.Sprintf("tenant%d", t))
		if err != nil {
			b.Fatal(err)
		}
		k, _, _ := d.CreatePreAuthKey(ctx, db.CreatePreAuthKeyParams{UserID: u.ID, Reusable: true, TTL: time.Hour})
		for m := 0; m < perTenant; m++ {
			nk := key.NewPrivate[key.NodeKind]().Public()
			res, err := d.RegisterNode(ctx, db.RegisterParams{
				MachineKey: key.NewPrivate[key.MachineKind]().Public().String(), NodeKey: nk.String(),
				DiscoKey: key.NewPrivate[key.DiscoKind]().Public().String(), Hostname: fmt.Sprintf("m%d", m),
				AuthKey: k, Alloc: s.ipam.Next,
			})
			if err != nil {
				b.Fatal(err)
			}
			bs.ids, bs.keys, bs.owner = append(bs.ids, res.Node.ID), append(bs.keys, nk), append(bs.owner, t)
		}
	}
	if share && tenants > 1 {
		for t := 0; t < tenants; t++ {
			sh, err := d.ShareWith(ctx, bs.ids[t*perTenant], fmt.Sprintf("tenant%d", (t+1)%tenants), "")
			if err != nil {
				b.Fatal(err)
			}
			r, _ := d.GetUser(ctx, fmt.Sprintf("tenant%d", (t+1)%tenants))
			if err := d.AcceptShare(ctx, sh.ID, r.ID); err != nil {
				b.Fatal(err)
			}
		}
	}
	s.checkGeneration()
	return bs
}

// BuildMap runs for every machine of a tenant whenever anything it can see
// changes, so its cost times the tenant's size bounds how fast the server
// fans out an update.
func BenchmarkBuildMap(b *testing.B) {
	for _, c := range []struct {
		name               string
		tenants, perTenant int
		share              bool
	}{
		{"1tenant_100machines", 1, 100, false},
		{"1tenant_1000machines", 1, 1000, false},
		{"100tenants_10machines", 100, 10, false},
		{"100tenants_10machines_shares", 100, 10, true},
	} {
		b.Run(c.name, func(b *testing.B) {
			bs := newBenchServer(b, c.tenants, c.perTenant, c.share)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := bs.srv.BuildMap(ctx, bs.ids[i%len(bs.ids)]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// refreshPolicy rebuilds the relay's tenant table after every change.
func BenchmarkRefreshPolicy1000Machines(b *testing.B) {
	bs := newBenchServer(b, 100, 10, true)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bs.srv.refreshPolicy()
	}
}

// RelayAllowed runs for every relayed packet.
func BenchmarkRelayAllowed(b *testing.B) {
	bs := newBenchServer(b, 100, 10, true)
	n := len(bs.keys)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bs.srv.RelayAllowed(bs.keys[i%n], bs.keys[(i*7+1)%n])
	}
}

// BenchmarkUpdateFanOut is the server's total cost for one change in an
// account of 1,000 machines: rebuild the snapshot, then build and encode
// the new map for every machine (what the map streams send). Reported per
// change.
func BenchmarkUpdateFanOut1000(b *testing.B) {
	bs := newBenchServer(b, 1, 1000, false)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bs.srv.snapMu.Lock()
		bs.srv.snap = nil // as if the generation had just changed
		bs.srv.snapMu.Unlock()
		for _, id := range bs.ids {
			if _, err := bs.srv.BuildMapJSON(ctx, id); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkMapJSON1000 compares encoding one map with 999 peers from
// scratch (encoding/json) with assembling it from the snapshot's cached
// peer encodings (BuildMapJSON, what map streams use).
func BenchmarkMapJSON1000(b *testing.B) {
	bs := newBenchServer(b, 1, 1000, false)
	ctx := context.Background()
	m, err := bs.srv.BuildMap(ctx, bs.ids[0])
	if err != nil {
		b.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	b.Run("encoding-json", func(b *testing.B) {
		b.SetBytes(int64(len(raw)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := json.Marshal(m); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		b.SetBytes(int64(len(raw)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := bs.srv.BuildMapJSON(ctx, bs.ids[i%len(bs.ids)]); err != nil {
				b.Fatal(err)
			}
		}
	})
}
