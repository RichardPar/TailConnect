package disco

import (
	"net/netip"
	"reflect"
	"testing"

	"tailconnect/internal/key"
)

func TestSealOpen(t *testing.T) {
	a, b := key.NewPrivate[key.DiscoKind](), key.NewPrivate[key.DiscoKind]()
	nk := key.NewPrivate[key.NodeKind]().Public()
	msgs := []Message{
		&Ping{TxID: NewTxID(), NodeKey: nk},
		&Pong{TxID: NewTxID(), Src: netip.MustParseAddrPort("198.51.100.7:41641")},
		&Pong{TxID: NewTxID(), Src: netip.MustParseAddrPort("[2001:db8::7]:41641")},
		&CallMeMaybe{Endpoints: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("[fd00::1]:2")}},
		&CallMeMaybe{},
	}
	for _, m := range msgs {
		pkt := Seal(a, b.Public(), m)
		if !Looks(pkt) {
			t.Fatal("sealed packet not recognised")
		}
		sender, ok := Sender(pkt)
		if !ok || !sender.Equal(a.Public()) {
			t.Fatal("wrong sender")
		}
		got, err := Open(b, sender, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if cm, ok := m.(*CallMeMaybe); ok && len(cm.Endpoints) == 0 {
			if g := got.(*CallMeMaybe); len(g.Endpoints) != 0 {
				t.Fatal("empty CallMeMaybe decoded with endpoints")
			}
			continue
		}
		if !reflect.DeepEqual(got, m) {
			t.Fatalf("got %#v want %#v", got, m)
		}
	}
}

func TestForgedAndTampered(t *testing.T) {
	a, b, mallory := key.NewPrivate[key.DiscoKind](), key.NewPrivate[key.DiscoKind](), key.NewPrivate[key.DiscoKind]()
	pkt := Seal(mallory, b.Public(), &Ping{TxID: NewTxID()})
	// Mallory claims to be a by rewriting the sender key: the box no longer opens.
	pub := a.Public().Raw()
	copy(pkt[len(Magic):], pub[:])
	if _, err := Open(b, a.Public(), pkt); err == nil {
		t.Fatal("forged sender accepted")
	}
	good := Seal(a, b.Public(), &Ping{TxID: NewTxID()})
	good[len(good)-1] ^= 1
	if _, err := Open(b, a.Public(), good); err == nil {
		t.Fatal("tampered packet accepted")
	}
	wg := make([]byte, 148)
	wg[0] = 1
	if Looks(wg) {
		t.Fatal("WireGuard packet classified as disco")
	}
}
