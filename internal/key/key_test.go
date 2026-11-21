package key

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicRoundTrip(t *testing.T) {
	priv := NewPrivate[NodeKind]()
	pub := priv.Public()
	if pub.IsZero() {
		t.Fatal("derived public key is zero")
	}
	s := pub.String()
	if !strings.HasPrefix(s, "nodekey:") {
		t.Fatalf("bad prefix: %s", s)
	}
	got, err := ParsePublic[NodeKind](s)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Fatal("round trip mismatch")
	}
}

func TestPrivateRoundTrip(t *testing.T) {
	priv := NewPrivate[MachineKind]()
	b, err := priv.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePrivate[MachineKind](string(b))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(priv) || !got.Public().Equal(priv.Public()) {
		t.Fatal("private round trip mismatch")
	}
	if strings.Contains(priv.String(), string(b[len("mprivkey:"):])) {
		t.Fatal("String() leaked private key material")
	}
}

func TestWrongPrefixRejected(t *testing.T) {
	pub := NewPrivate[NodeKind]().Public()
	if _, err := ParsePublic[DiscoKind](pub.String()); err == nil {
		t.Fatal("expected disco parser to reject a node key")
	}
	if _, err := ParsePublic[NodeKind]("nodekey:abcd"); err == nil {
		t.Fatal("expected short key to be rejected")
	}
}

func TestJSONZeroAndValue(t *testing.T) {
	type wrap struct {
		K NodePublic
	}
	var zero wrap
	b, _ := json.Marshal(zero)
	if string(b) != `{"K":""}` {
		t.Fatalf("zero key json = %s", b)
	}
	in := wrap{K: NewPrivate[NodeKind]().Public()}
	b, _ = json.Marshal(in)
	var out wrap
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !out.K.Equal(in.K) {
		t.Fatal("json round trip mismatch")
	}
}

func TestParsePrivateRefusesZero(t *testing.T) {
	for _, s := range []string{"", "  \n", "relayprivkey:" + strings.Repeat("00", 32)} {
		if _, err := ParsePrivate[RelayKind](s); err == nil {
			t.Errorf("ParsePrivate(%q) accepted a zero key", s)
		}
	}
	k := NewPrivate[RelayKind]()
	text, _ := k.MarshalText()
	if got, err := ParsePrivate[RelayKind](string(text) + "\n"); err != nil || got != k {
		t.Fatalf("round trip: %v", err)
	}
}
