package trayicon

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"testing"
)

func TestICO(t *testing.T) {
	b := ICO(Connected, 16, 32, 256)
	var h struct{ Reserved, Type, Count uint16 }
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &h); err != nil || h.Type != 1 || h.Count != 3 {
		t.Fatalf("header %+v, %v", h, err)
	}
	// The first entry's PNG decodes at the right size.
	var e struct {
		W, H, Pal, Res uint8
		Planes, BPP    uint16
		Size, Offset   uint32
	}
	binary.Read(bytes.NewReader(b[6:]), binary.LittleEndian, &e)
	img, err := png.Decode(bytes.NewReader(b[e.Offset : e.Offset+e.Size]))
	if err != nil || img.Bounds().Dx() != 16 {
		t.Fatalf("entry 0: %v, %v", img.Bounds(), err)
	}
}

func TestRenderCorners(t *testing.T) {
	for _, s := range []State{Connected, Disconnected, Problem} {
		img := Render(s, 32)
		if img.NRGBAAt(0, 0).A != 0 {
			t.Errorf("state %d: corner not transparent", s)
		}
		if img.NRGBAAt(16, 2).A != 0xff {
			t.Errorf("state %d: edge not opaque", s)
		}
	}
}

// TRAYICON_PREVIEW=out.png go test -run Preview ./internal/trayicon writes
// every state at several sizes on light and dark backgrounds.
func TestPreview(t *testing.T) {
	out := os.Getenv("TRAYICON_PREVIEW")
	if out == "" {
		t.Skip("set TRAYICON_PREVIEW=file.png")
	}
	sizes := []int{16, 20, 24, 32, 128}
	w := 10
	for _, sz := range sizes {
		w += 3 * (sz + 10)
	}
	sheet := image.NewNRGBA(image.Rect(0, 0, w+20, 2*150))
	for row, bg := range []color.NRGBA{{0xf3, 0xf3, 0xf3, 0xff}, {0x20, 0x20, 0x20, 0xff}} {
		draw.Draw(sheet, image.Rect(0, row*150, w+20, row*150+150), &image.Uniform{bg}, image.Point{}, draw.Src)
		x := 10
		for _, st := range []State{Connected, Disconnected, Problem} {
			for _, sz := range sizes {
				r := image.Rect(x, row*150+(150-sz)/2, x+sz, row*150+(150-sz)/2+sz)
				draw.Draw(sheet, r, Render(st, sz), image.Point{}, draw.Over)
				x += sz + 10
			}
			x += 10
		}
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	png.Encode(f, sheet)
}
