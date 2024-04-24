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
	"flag"
	"log"
	"net/http"

	"github.com/google/dnsmasq_exporter/collector"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
)

var (
	listen = flag.String("listen",
		"localhost:9153",
		"listen address")

	exposeLeases = flag.Bool("expose_leases",
		false,
		"expose dnsmasq leases as metrics (high cardinality)")

	leasesPath = flag.String("leases_path",
		"/var/lib/misc/dnsmasq.leases",
		"path to the dnsmasq leases file")

	dnsmasqAddr = flag.String("dnsmasq",
		"localhost:53",
		"dnsmasq host:port address")
	dnsmasqProtocol = flag.String("protocol",
		"udp",
		"connect using udp or tcp")

	metricsPath = flag.String("metrics_path",
		"/metrics",
		"path under which metrics are served")
)

func init() {
	prometheus.MustRegister(version.NewCollector("dnsmasq_exporter"))
}

func main() {
	flag.Parse()

	var (
		dnsClient = &dns.Client{
			SingleInflight: true,
			Net:            *dnsmasqProtocol,
		}
		cfg = collector.Config{
			DnsClient:    dnsClient,
			DnsmasqAddr:  *dnsmasqAddr,
			LeasesPath:   *leasesPath,
			ExposeLeases: *exposeLeases,
		}
		collector = collector.New(cfg)
		reg       = prometheus.NewRegistry()
	)

	reg.MustRegister(collector)

	http.Handle(*metricsPath, promhttp.HandlerFor(
		prometheus.Gatherers{prometheus.DefaultGatherer, reg},
		promhttp.HandlerOpts{},
	))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
      <head><title>Dnsmasq Exporter</title></head>
      <body>
      <h1>Dnsmasq Exporter</h1>
      <p><a href="` + *metricsPath + `">Metrics</a></p>
      </body></html>`))
	})
	log.Println("Listening on", *listen)
	log.Println("Service metrics under", *metricsPath)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
