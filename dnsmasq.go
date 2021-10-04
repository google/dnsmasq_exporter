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
	"net/http"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
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

	leasesPath = flag.String("leases_path",
		"/var/lib/misc/dnsmasq.leases",
		"path to the dnsmasq leases file")

	dnsmasqAddr = flag.String("dnsmasq",
		"localhost:53",
		"dnsmasq host:port address")
	metricsPath = flag.String("metrics_path",
		"/metrics",
		"path under which metrics are served")
)

func init() {
	prometheus.MustRegister(version.NewCollector("dnsmasq_exporter"))
}

func main() {
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)

	flag.Parse()

	var (
		dnsClient = &dns.Client{
			SingleInflight: true,
		}
		collector = collector.New(logger, dnsClient, *dnsmasqAddr, *leasesPath)
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
	level.Info(logger).Log("msg", "now listening", "listen_addr", *listen, "metrics_path", *metricsPath)

	if err := http.ListenAndServe(*listen, nil); err != nil {
		level.Error(logger).Log("msg", "listener failed", "err", err)
		os.Exit(1)
	}
}
