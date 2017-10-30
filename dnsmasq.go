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

// Binary dnsmasq_exporter is a Prometheus exporter for dnsmasq statistics.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"golang.org/x/sync/errgroup"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	listen = flag.String("listen",
		"localhost:9153",
		"listen address")

	leasesPath = flag.String("leases_path",
		"/var/lib/misc/dnsmasq.leases",
		"path to the dnsmasq leases file")
)

var (
	// floatMetrics contains prometheus Gauges, keyed by the stats DNS record
	// they correspond to.
	floatMetrics = map[string]prometheus.Gauge{
		"cachesize.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_cachesize",
			Help: "configured size of the DNS cache",
		}),

		"insertions.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_insertions",
			Help: "DNS cache insertions",
		}),

		"evictions.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_evictions",
			Help: "DNS cache exictions: numbers of entries which replaced an unexpired cache entry",
		}),

		"misses.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_misses",
			Help: "DNS cache misses: queries which had to be forwarded",
		}),

		"hits.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_hits",
			Help: "DNS queries answered locally (cache hits)",
		}),

		"auth.bind.": prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dnsmasq_auth",
			Help: "DNS queries for authoritative zones",
		}),
	}

	leases = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "dnsmasq_leases",
		Help: "Number of DHCP leases handed out",
	})
)

func init() {
	for _, g := range floatMetrics {
		prometheus.MustRegister(g)
	}
	prometheus.MustRegister(leases)
}

// From https://manpages.debian.org/stretch/dnsmasq-base/dnsmasq.8.en.html:
// The cache statistics are also available in the DNS as answers to queries of
// class CHAOS and type TXT in domain bind. The domain names are cachesize.bind,
// insertions.bind, evictions.bind, misses.bind, hits.bind, auth.bind and
// servers.bind. An example command to query this, using the dig utility would
// be:
//     dig +short chaos txt cachesize.bind

func main() {
	flag.Parse()
	promHandler := promhttp.Handler()
	dnsClient := &dns.Client{
		SingleInflight: true,
	}
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		var eg errgroup.Group

		eg.Go(func() error {
			msg := &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id: dns.Id(),
				},
				Question: []dns.Question{
					dns.Question{"cachesize.bind.", dns.TypeTXT, dns.ClassCHAOS},
					dns.Question{"insertions.bind.", dns.TypeTXT, dns.ClassCHAOS},
					dns.Question{"evictions.bind.", dns.TypeTXT, dns.ClassCHAOS},
					dns.Question{"misses.bind.", dns.TypeTXT, dns.ClassCHAOS},
					dns.Question{"hits.bind.", dns.TypeTXT, dns.ClassCHAOS},
					dns.Question{"auth.bind.", dns.TypeTXT, dns.ClassCHAOS},
					dns.Question{"servers.bind.", dns.TypeTXT, dns.ClassCHAOS},
				},
			}
			in, _, err := dnsClient.Exchange(msg, "127.0.0.1:53")
			if err != nil {
				return err
			}
			for _, a := range in.Answer {
				txt, ok := a.(*dns.TXT)
				if !ok {
					continue
				}
				switch txt.Hdr.Name {
				case "servers.bind.":
					// TODO: parse <server> <successes> <errors>, also with multiple upstreams
				default:
					g, ok := floatMetrics[txt.Hdr.Name]
					if !ok {
						continue // ignore unexpected answer from dnsmasq
					}
					if got, want := len(txt.Txt), 1; got != want {
						return fmt.Errorf("stats DNS record %q: unexpected number of replies: got %d, want %d", txt.Hdr.Name, got, want)
					}
					f, err := strconv.ParseFloat(txt.Txt[0], 64)
					if err != nil {
						return err
					}
					g.Set(f)
				}
			}
			return nil
		})

		eg.Go(func() error {
			f, err := os.Open(*leasesPath)
			if err != nil {
				return err
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			var lines float64
			for scanner.Scan() {
				lines++
			}
			if err := scanner.Err(); err != nil {
				return err
			}
			leases.Set(lines)
			return nil
		})

		if err := eg.Wait(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		promHandler.ServeHTTP(w, r)
	})
	log.Fatal(http.ListenAndServe(*listen, nil))
}
