// Command tput measures TCP throughput and round-trip latency between two
// hosts, for tests/perf/throughput.sh (a minimal iperf substitute with no
// dependencies).
//
//	tput -listen ADDR                    serve both tests
//	tput -connect ADDR -stream 5s        send for 5s, print MB/s
//	tput -connect ADDR -rtt 2000         2000 one-byte round trips, print latency
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"time"
)

func main() {
	listen := flag.String("listen", "", "serve on this address")
	connect := flag.String("connect", "", "server address")
	stream := flag.Duration("stream", 0, "throughput test duration")
	rtt := flag.Int("rtt", 0, "number of round trips")
	flag.Parse()
	var err error
	switch {
	case *listen != "":
		err = serve(*listen)
	case *connect != "" && *stream > 0:
		err = runStream(*connect, *stream)
	case *connect != "" && *rtt > 0:
		err = runRTT(*connect, *rtt)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tput:", err)
		os.Exit(1)
	}
}

func serve(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			r := bufio.NewReader(c)
			mode, err := r.ReadByte()
			if err != nil {
				return
			}
			switch mode {
			case 'S': // stream: discard, then report the byte count
				n, _ := io.Copy(io.Discard, r)
				fmt.Fprintf(os.Stderr, "received %d bytes\n", n)
			case 'E': // echo single bytes
				buf := make([]byte, 1)
				for {
					if _, err := io.ReadFull(r, buf); err != nil {
						return
					}
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}
		}(c)
	}
}

func runStream(addr string, d time.Duration) error {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.Write([]byte{'S'}); err != nil {
		return err
	}
	buf := make([]byte, 128<<10)
	var sent int64
	start := time.Now()
	for time.Since(start) < d {
		n, err := c.Write(buf)
		sent += int64(n)
		if err != nil {
			return err
		}
	}
	el := time.Since(start).Seconds()
	fmt.Printf("%.1f MB/s (%.0f Mbit/s)\n", float64(sent)/el/1e6, float64(sent)*8/el/1e6)
	return nil
}

func runRTT(addr string, n int) error {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	if _, err := c.Write([]byte{'E'}); err != nil {
		return err
	}
	b := []byte{'x'}
	lat := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		if _, err := c.Write(b); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		lat = append(lat, time.Since(t0))
	}
	slices.Sort(lat)
	us := func(d time.Duration) float64 { return float64(d.Microseconds()) }
	fmt.Printf("p50 %.0fµs p99 %.0fµs\n", us(lat[len(lat)/2]), us(lat[len(lat)*99/100]))
	return nil
}
