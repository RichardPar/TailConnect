package password

import (
	"strings"
	"testing"
	"time"
)

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("format: %s", h)
	}
	if !Verify("correct horse battery", h) {
		t.Fatal("right password rejected")
	}
	if Verify("correct horse batterY", h) || Verify("", h) {
		t.Fatal("wrong password accepted")
	}
	h2, _ := Hash("correct horse battery")
	if h == h2 {
		t.Fatal("hashes must be salted")
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdA$aGFzaA"} {
		if Verify("x", bad) {
			t.Errorf("malformed hash %q matched", bad)
		}
	}
}

func TestCheck(t *testing.T) {
	if Check("short") == nil || Check(strings.Repeat("x", 300)) == nil {
		t.Fatal("bad lengths accepted")
	}
	if err := Check("ten chars!"); err != nil {
		t.Fatal(err)
	}
}

func TestDummyCost(t *testing.T) {
	h, _ := Hash("some password here")
	t0 := time.Now()
	Verify("guess guess guess", h)
	real := time.Since(t0)
	t0 = time.Now()
	VerifyDummy("guess guess guess")
	dummy := time.Since(t0)
	if dummy < real/3 {
		t.Fatalf("dummy verify too cheap: %v vs %v", dummy, real)
	}
}

// Hashing cost bounds sign-ins and sign-ups per second (the portal runs at
// most four at once).
func BenchmarkHash(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Hash("correct horse battery"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	h, _ := Hash("correct horse battery")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify("correct horse battery", h)
	}
}
