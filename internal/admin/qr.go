package admin

import (
	"fmt"
	"net/url"
	"strings"

	"rsc.io/qr"
)

// JoinURL is what an auth key's QR code holds. The Android app opens
// tailconnect://join links with its form filled in: point the device's
// camera at the code, open the link, check the name, tap Connect.
func JoinURL(server, authKey string) string {
	q := url.Values{}
	if server != "" {
		q.Set("server", server)
	}
	q.Set("key", authKey)
	return "tailconnect://join?" + q.Encode()
}

// qrSVG draws text as a QR code: dark modules on white with the standard
// four-module quiet zone, so it scans in dark mode too.
func qrSVG(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := c.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="QR code">`, n, n)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
