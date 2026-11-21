package autotls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DuckDNS sets DNS-01 TXT records through DuckDNS's update API. A DuckDNS
// name has one TXT record, served for the name and every name under it
// (so for _acme-challenge.NAME.duckdns.org too).
type DuckDNS struct {
	Token string
	// BaseURL is DuckDNS's API (tests override it).
	BaseURL string
	Client  *http.Client
}

// DuckDNSName returns the DuckDNS name ("tailconnect") a domain
// ("tailconnect.duckdns.org", or "vpn.tailconnect.duckdns.org") belongs to.
func DuckDNSName(domain string) (string, error) {
	rest, ok := strings.CutSuffix(strings.ToLower(strings.TrimSuffix(domain, ".")), ".duckdns.org")
	name := rest[strings.LastIndex(rest, ".")+1:]
	if !ok || name == "" || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		return "", fmt.Errorf("%q isn't a DuckDNS name (NAME.duckdns.org)", domain)
	}
	return name, nil
}

func (d *DuckDNS) SetTXT(ctx context.Context, domain, value string) error {
	return d.update(ctx, domain, url.Values{"txt": {value}})
}

func (d *DuckDNS) ClearTXT(ctx context.Context, domain string) error {
	return d.update(ctx, domain, url.Values{"txt": {"removed"}, "clear": {"true"}})
}

func (d *DuckDNS) update(ctx context.Context, domain string, q url.Values) error {
	name, err := DuckDNSName(domain)
	if err != nil {
		return err
	}
	if d.Token == "" {
		return errors.New("no DuckDNS token")
	}
	base := d.BaseURL
	if base == "" {
		base = "https://www.duckdns.org"
	}
	q.Set("domains", name)
	q.Set("token", d.Token)
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/update?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	hc := d.Client
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		// The URL holds the token: don't let it reach the logs.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("DuckDNS: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	answer, _, _ := strings.Cut(strings.TrimSpace(string(body)), "\n")
	if resp.StatusCode != http.StatusOK || answer != "OK" {
		return fmt.Errorf("DuckDNS refused the update for %s.duckdns.org (HTTP %d, answer %q): check the token", name, resp.StatusCode, answer)
	}
	return nil
}
