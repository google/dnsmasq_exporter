package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestDnsmasqExporter(t *testing.T) {
	// NOTE(stapelberg): dnsmasq disables DNS operation upon --port=0 (as
	// opposed to picking a free port). Hence, we must pick one. This is
	// inherently prone to race conditions: another process could grab the port
	// between our ln.Close() and dnsmasq’s bind(). Ideally, dnsmasq would
	// support grabbing a free port and announcing it, or inheriting a listening
	// socket à la systemd socket activation.

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()

	dnsmasq := exec.Command(
		"dnsmasq",
		"--port="+port,
		"--no-daemon",
		"--cache-size=666",
		"--bind-interfaces",
		"--interface=lo")
	dnsmasq.Stderr = os.Stderr
	fmt.Printf("starting %v\n", dnsmasq.Args)
	if err := dnsmasq.Start(); err != nil {
		t.Fatal(err)
	}
	defer dnsmasq.Process.Kill()

	// Wait until dnsmasq started up
	resolver := &dns.Client{}
	for {
		// Cause a cache miss (dnsmasq must forward this query)
		var m dns.Msg
		m.SetQuestion("localhost.", dns.TypeA)
		if _, _, err := resolver.Exchange(&m, "localhost:"+port); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond) // do not hog the CPU
	}

	s := &server{
		promHandler: promhttp.Handler(),
		dnsClient: &dns.Client{
			SingleInflight: true,
		},
		dnsmasqAddr: "localhost:" + port,
		leasesPath:  "testdata/dnsmasq.leases",
	}

	t.Run("first", func(t *testing.T) {
		metrics := fetchMetrics(t, s)
		want := map[string]string{
			"dnsmasq_leases":    "2",
			"dnsmasq_cachesize": "666",
			"dnsmasq_hits":      "1",
			"dnsmasq_misses":    "0",
		}
		for key, val := range want {
			if got, want := metrics[key], val; got != want {
				t.Errorf("metric %q: got %q, want %q", key, got, want)
			}
		}
	})

	t.Run("second", func(t *testing.T) {
		metrics := fetchMetrics(t, s)
		want := map[string]string{
			"dnsmasq_leases":    "2",
			"dnsmasq_cachesize": "666",
			"dnsmasq_hits":      "2",
			"dnsmasq_misses":    "0",
		}
		for key, val := range want {
			if got, want := metrics[key], val; got != want {
				t.Errorf("metric %q: got %q, want %q", key, got, want)
			}
		}
	})

	// Cause a cache miss (dnsmasq must forward this query)
	var m dns.Msg
	m.SetQuestion("no.such.domain.invalid.", dns.TypeA)
	if _, _, err := resolver.Exchange(&m, "localhost:"+port); err != nil {
		t.Fatal(err)
	}

	t.Run("after query", func(t *testing.T) {
		metrics := fetchMetrics(t, s)
		want := map[string]string{
			"dnsmasq_leases":    "2",
			"dnsmasq_cachesize": "666",
			"dnsmasq_hits":      "3",
			"dnsmasq_misses":    "1",
		}
		for key, val := range want {
			if got, want := metrics[key], val; got != want {
				t.Errorf("metric %q: got %q, want %q", key, got, want)
			}
		}
	})
}

func fetchMetrics(t *testing.T, s *server) map[string]string {
	rec := httptest.NewRecorder()
	s.metrics(rec, httptest.NewRequest("GET", "/metrics", nil))
	resp := rec.Result()
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		b, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("unexpected HTTP status: got %v (%v), want %v", resp.Status, string(b), want)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	metrics := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) < 2 {
			continue
		}
		if !strings.HasPrefix(parts[0], "dnsmasq_") {
			continue
		}
		metrics[parts[0]] = parts[1]
	}
	return metrics
}
