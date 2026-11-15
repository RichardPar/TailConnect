package db

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"tailconnect/internal/ipam"
)

func benchDB(b *testing.B) *DB {
	d, err := Open(filepath.Join(b.TempDir(), "c.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { d.Close() })
	return d
}

// Registration: validate and consume a key, allocate addresses, pick a
// unique name, all in one transaction. Bounds how fast a fleet can join.
func BenchmarkRegisterNode(b *testing.B) {
	d := benchDB(b)
	u, _ := d.CreateUser(ctx, "fleet")
	k, _, _ := d.CreatePreAuthKey(ctx, CreatePreAuthKeyParams{UserID: u.ID, Reusable: true, TTL: time.Hour})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := d.RegisterNode(ctx, RegisterParams{
			MachineKey: fmt.Sprintf("m%d", i), NodeKey: fmt.Sprintf("n%d", i), Hostname: "worker",
			AuthKey: k, Alloc: ipam.Default().Next,
		}); err != nil {
			b.Fatal(err)
		}
	}
}

// Endpoint/status reports arrive every few seconds from every machine.
func BenchmarkUpdateNodeStatus(b *testing.B) {
	d := benchDB(b)
	u, _ := d.CreateUser(ctx, "acme")
	k, _, _ := d.CreatePreAuthKey(ctx, CreatePreAuthKeyParams{UserID: u.ID, TTL: time.Hour})
	res, err := reg(d, "m1", "n1", "laptop", k)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := d.UpdateNodeStatus(ctx, res.Node.ID, NodeStatus{HomeRelay: 1 + i%2}); err != nil {
			b.Fatal(err)
		}
	}
}

// ListNodes over 1,000 machines: the database part of a snapshot rebuild.
func BenchmarkListNodes1000(b *testing.B) {
	d := benchDB(b)
	u, _ := d.CreateUser(ctx, "acme")
	k, _, _ := d.CreatePreAuthKey(ctx, CreatePreAuthKeyParams{UserID: u.ID, Reusable: true, TTL: time.Hour})
	for i := 0; i < 1000; i++ {
		if _, err := reg(d, fmt.Sprintf("m%d", i), fmt.Sprintf("n%d", i), "worker", k); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, err := d.ListNodes(ctx, 0); err != nil || len(n) != 1000 {
			b.Fatal(len(n), err)
		}
	}
}
