// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
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

	testDataFilePath := os.Getenv("TESTDATA_FILE_PATH")
	if testDataFilePath == "" {
		testDataFilePath = "./testdata/dnsmasq.leases"
	}

	cfg := Config{
		DnsClient: &dns.Client{
			SingleInflight: true,
		},
		DnsmasqAddr:  "localhost:" + port,
		LeasesPath:   testDataFilePath,
		ExposeLeases: false,
	}

	c := New(cfg)

	t.Run("first", func(t *testing.T) {
		metrics := fetchMetrics(t, c)
		want := map[string]string{
			"dnsmasq_leases":    "2",
			"dnsmasq_cachesize": "666",
			"dnsmasq_hits":      "5",
			"dnsmasq_misses":    "0",
		}
		for key, val := range want {
			if got, want := metrics[key], val; got != want {
				t.Errorf("metric %q: got %q, want %q", key, got, want)
			}
		}
	})

	t.Run("second", func(t *testing.T) {
		metrics := fetchMetrics(t, c)
		want := map[string]string{
			"dnsmasq_leases":    "2",
			"dnsmasq_cachesize": "666",
			"dnsmasq_hits":      "12",
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
		metrics := fetchMetrics(t, c)
		want := map[string]string{
			"dnsmasq_leases":    "2",
			"dnsmasq_cachesize": "666",
			"dnsmasq_hits":      "19",
			"dnsmasq_misses":    "1",
		}
		for key, val := range want {
			if got, want := metrics[key], val; got != want {
				t.Errorf("metric %q: got %q, want %q", key, got, want)
			}
		}
	})

	t.Run("should not expose lease information when disabled", func(t *testing.T) {
		metrics := fetchMetrics(t, c)
		for key := range metrics {
			if strings.Contains(key, "dnsmasq_lease_expiry") {
				t.Errorf("lease information should not be exposed when disabled: %v", key)
			}
		}
	})

	c.cfg.ExposeLeases = true

	t.Run("with high-cardinality lease metrics enabled", func(t *testing.T) {
		metrics := fetchMetrics(t, c)
		want := map[string]string{
			"dnsmasq_leases":    "2",
			"dnsmasq_cachesize": "666",
			"dnsmasq_hits":      "33",
			"dnsmasq_misses":    "1",
			"dnsmasq_lease_expiry{client_id=\"00:00:00:00:00:00\",computer_name=\"host-1\",ip_addr=\"10.10.10.10\",mac_addr=\"00:00:00:00:00:00\"}": "1.625595932e+09",
			"dnsmasq_lease_expiry{client_id=\"00:00:00:00:00:01\",computer_name=\"host-2\",ip_addr=\"10.10.10.11\",mac_addr=\"00:00:00:00:00:01\"}": "0",
		}
		for key, val := range want {
			if got, want := metrics[key], val; got != want {
				t.Errorf("metric %q: got %q, want %q", key, got, want)
			}
		}
	})

	c.cfg.LeasesPath = "testdata/dnsmasq.leases.does.not.exists"

	t.Run("without leases file", func(t *testing.T) {
		metrics := fetchMetrics(t, c)
		want := map[string]string{
			"dnsmasq_leases":    "0",
			"dnsmasq_cachesize": "666",
			"dnsmasq_hits":      "40",
			"dnsmasq_misses":    "1",
		}
		for key, val := range want {
			if got, want := metrics[key], val; got != want {
				t.Errorf("metric %q: got %q, want %q", key, got, want)
			}
		}
	})

}

func fetchMetrics(t *testing.T, c *Collector) map[string]string {
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	resp := rec.Result()
	if got, want := resp.StatusCode, http.StatusOK; got != want {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected HTTP status: got %v (%v), want %v", resp.Status, string(b), want)
	}
	body, err := io.ReadAll(resp.Body)
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
