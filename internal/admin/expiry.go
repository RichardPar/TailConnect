package admin

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// maxExpiryMonths bounds a machine key lifetime given in months.
const maxExpiryMonths = 120

// NodeExpiry works out when a machine's key should expire from a choice:
//
//	"never"        no expiry (the zero time)
//	"default"      the server's lifetime def from now (never if def is 0)
//	"6mo", "12mo"  that many months from now (1 to 120)
//	"2027-06-30"   the end of that day in loc
//	RFC 3339 time  that moment
//
// Times must be in the future.
func NodeExpiry(choice string, now time.Time, def time.Duration, loc *time.Location) (time.Time, error) {
	choice = strings.TrimSpace(choice)
	var at time.Time
	switch {
	case choice == "never":
		return time.Time{}, nil
	case choice == "default":
		if def <= 0 {
			return time.Time{}, nil
		}
		return now.Add(def), nil
	case strings.HasSuffix(choice, "mo"):
		n, err := strconv.Atoi(strings.TrimSuffix(choice, "mo"))
		if err != nil || n < 1 || n > maxExpiryMonths {
			return time.Time{}, fmt.Errorf("bad expiry %q: months must be 1 to %d (e.g. 12mo)", choice, maxExpiryMonths)
		}
		return now.AddDate(0, n, 0), nil
	default:
		if d, err := time.ParseInLocation(time.DateOnly, choice, loc); err == nil {
			at = d.AddDate(0, 0, 1).Add(-time.Second) // the end of that day
		} else if t, err := time.Parse(time.RFC3339, choice); err == nil {
			at = t
		} else {
			return time.Time{}, fmt.Errorf(`bad expiry %q: use "never", "default", months (e.g. 12mo) or a date (YYYY-MM-DD)`, choice)
		}
	}
	if !at.After(now) {
		return time.Time{}, errors.New("the expiry date must be in the future")
	}
	if at.After(now.AddDate(0, maxExpiryMonths, 0)) {
		return time.Time{}, fmt.Errorf("the expiry date must be within %d years", maxExpiryMonths/12)
	}
	return at, nil
}
