// Package trayicon draws the TailConnect icon (a three-node mesh on a
// rounded square) in each state, at any size, as PNG or .ico data. It is
// plain Go so the images can be checked on any platform.
package trayicon

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// State selects the icon's colours.
type State int

const (
	Connected    State = iota // teal
	Disconnected              // grey
	Problem                   // amber, with an exclamation mark
)

var backgrounds = map[State]color.NRGBA{
	Connected:    {0x0f, 0x8f, 0x86, 0xff},
	Disconnected: {0x7a, 0x80, 0x8a, 0xff},
	Problem:      {0xd9, 0x77, 0x06, 0xff},
}

const supersample = 4

// Render draws the icon at size×size pixels.
func Render(s State, size int) *image.NRGBA {
	n := size * supersample
	big := image.NewNRGBA(image.Rect(0, 0, n, n))
	f := float64(n)
	bg := backgrounds[s]
	white := color.NRGBA{0xff, 0xff, 0xff, 0xff}

	// Rounded square filling the icon.
	radius := 0.22 * f
	fill(big, func(x, y float64) bool { return inRoundedRect(x, y, 0, 0, f, f, radius) }, bg)

	// Mesh: three nodes joined by lines.
	nodes := [3][2]float64{{0.50, 0.24}, {0.24, 0.72}, {0.76, 0.72}}
	if s == Problem {
		nodes = [3][2]float64{{0.30, 0.26}, {0.22, 0.74}, {0.56, 0.62}}
	}
	line := 0.075 * f
	for i := range nodes {
		a, b := nodes[i], nodes[(i+1)%3]
		ax, ay, bx, by := a[0]*f, a[1]*f, b[0]*f, b[1]*f
		fill(big, func(x, y float64) bool { return segDist(x, y, ax, ay, bx, by) <= line/2 }, white)
	}
	r := 0.12 * f
	for _, p := range nodes {
		cx, cy := p[0]*f, p[1]*f
		fill(big, func(x, y float64) bool { return math.Hypot(x-cx, y-cy) <= r }, white)
	}
	if s == Problem { // "!" on the right
		bar := 0.11 * f
		cx := 0.80 * f
		fill(big, func(x, y float64) bool {
			return segDist(x, y, cx, 0.20*f, cx, 0.58*f) <= bar/2 || math.Hypot(x-cx, y-0.78*f) <= bar*0.62
		}, white)
	}
	return downsample(big, size)
}

func fill(img *image.NRGBA, in func(x, y float64) bool, c color.NRGBA) {
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if in(float64(x)+0.5, float64(y)+0.5) {
				img.SetNRGBA(x, y, c)
			}
		}
	}
}

func inRoundedRect(x, y, x0, y0, x1, y1, r float64) bool {
	if x < x0 || x > x1 || y < y0 || y > y1 {
		return false
	}
	cx := math.Max(x0+r, math.Min(x, x1-r))
	cy := math.Max(y0+r, math.Min(y, y1-r))
	return math.Hypot(x-cx, y-cy) <= r
}

func segDist(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

// downsample averages supersample×supersample blocks (premultiplied, so
// edges blend correctly).
func downsample(big *image.NRGBA, size int) *image.NRGBA {
	out := image.NewNRGBA(image.Rect(0, 0, size, size))
	k := supersample
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for j := 0; j < k; j++ {
				for i := 0; i < k; i++ {
					c := big.NRGBAAt(x*k+i, y*k+j)
					al := float64(c.A)
					r += float64(c.R) * al
					g += float64(c.G) * al
					b += float64(c.B) * al
					a += al
				}
			}
			if a == 0 {
				continue
			}
			out.SetNRGBA(x, y, color.NRGBA{uint8(r/a + 0.5), uint8(g/a + 0.5), uint8(b/a + 0.5), uint8(a/float64(k*k) + 0.5)})
		}
	}
	return out
}

// PNG returns the icon as PNG data.
func PNG(s State, size int) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, Render(s, size))
	return buf.Bytes()
}

// ICO returns a .ico file with the icon at the given sizes (PNG-compressed
// entries, which Windows Vista and later read).
func ICO(s State, sizes ...int) []byte {
	var imgs [][]byte
	for _, sz := range sizes {
		imgs = append(imgs, PNG(s, sz))
	}
	var buf bytes.Buffer
	w := func(v any) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	w(uint16(0))
	w(uint16(1)) // icon
	w(uint16(len(sizes)))
	off := 6 + 16*len(sizes)
	for i, sz := range sizes {
		d := uint8(sz)
		if sz >= 256 {
			d = 0
		}
		w(d)          // width
		w(d)          // height
		w(uint8(0))   // palette
		w(uint8(0))   // reserved
		w(uint16(1))  // planes
		w(uint16(32)) // bits per pixel
		w(uint32(len(imgs[i])))
		w(uint32(off))
		off += len(imgs[i])
	}
	for _, b := range imgs {
		buf.Write(b)
	}
	return buf.Bytes()
}
