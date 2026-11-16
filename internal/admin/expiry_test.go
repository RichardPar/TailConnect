package admin

import (
	"testing"
	"time"
)

func TestNodeExpiry(t *testing.T) {
	loc := time.FixedZone("X", 2*3600)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, loc)
	def := 180 * 24 * time.Hour
	for _, c := range []struct {
		in   string
		want time.Time
	}{
		{"never", time.Time{}},
		{"default", now.Add(def)},
		{"6mo", time.Date(2027, 5, 16, 12, 0, 0, 0, loc)},
		{"12mo", time.Date(2027, 11, 16, 12, 0, 0, 0, loc)},
		{"24mo", time.Date(2028, 11, 16, 12, 0, 0, 0, loc)},
		{"2027-06-30", time.Date(2027, 6, 30, 23, 59, 59, 0, loc)},
		{"2026-11-16", time.Date(2026, 11, 16, 23, 59, 59, 0, loc)}, // later today
		{"2027-01-01T08:00:00Z", time.Date(2027, 1, 1, 8, 0, 0, 0, time.UTC)},
	} {
		got, err := NodeExpiry(c.in, now, def, loc)
		if err != nil || !got.Equal(c.want) {
			t.Errorf("%s: %v %v, want %v", c.in, got, err, c.want)
		}
	}
	if got, err := NodeExpiry("default", now, 0, loc); err != nil || !got.IsZero() {
		t.Errorf("default with no server lifetime: %v %v", got, err)
	}
	for _, bad := range []string{"", "0mo", "121mo", "xmo", "2026-11-15", "2026-02-30", "2037-01-01", "soon", "180d"} {
		if _, err := NodeExpiry(bad, now, def, loc); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
