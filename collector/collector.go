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

// Package collector collects dnsmasq statistics as a Prometheus collector.
package collector

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
)

var (
	// floatMetrics contains prometheus Gauges, keyed by the stats DNS record
	// they correspond to.
	floatMetrics = map[string]*prometheus.Desc{
		"cachesize.bind.": prometheus.NewDesc(
			"dnsmasq_cachesize",
			"configured size of the DNS cache",
			nil, nil,
		),

		"insertions.bind.": prometheus.NewDesc(
			"dnsmasq_insertions",
			"DNS cache insertions",
			nil, nil,
		),

		"evictions.bind.": prometheus.NewDesc(
			"dnsmasq_evictions",
			"DNS cache exictions: numbers of entries which replaced an unexpired cache entry",
			nil, nil,
		),

		"misses.bind.": prometheus.NewDesc(
			"dnsmasq_misses",
			"DNS cache misses: queries which had to be forwarded",
			nil, nil,
		),

		"hits.bind.": prometheus.NewDesc(
			"dnsmasq_hits",
			"DNS queries answered locally (cache hits)",
			nil, nil,
		),

		"auth.bind.": prometheus.NewDesc(
			"dnsmasq_auth",
			"DNS queries for authoritative zones",
			nil, nil,
		),
	}

	serversMetrics = map[string]*prometheus.Desc{
		"queries": prometheus.NewDesc(
			"dnsmasq_servers_queries",
			"DNS queries on upstream server",
			[]string{"server"}, nil,
		),
		"queries_failed": prometheus.NewDesc(
			"dnsmasq_servers_queries_failed",
			"DNS queries failed on upstream server",
			[]string{"server"}, nil,
		),
	}

	// individual lease metrics have high cardinality and are thus disabled by
	// default, unless enabled with the -expose_leases flag
	leaseMetrics = prometheus.NewDesc(
		"dnsmasq_lease_expiry",
		"Expiry time for active DHCP leases",
		[]string{"mac_addr", "ip_addr", "computer_name", "client_id"},
		nil,
	)

	leases = prometheus.NewDesc(
		"dnsmasq_leases",
		"Number of DHCP leases handed out",
		nil, nil,
	)
)

// From https://manpages.debian.org/stretch/dnsmasq-base/dnsmasq.8.en.html:
// The cache statistics are also available in the DNS as answers to queries of
// class CHAOS and type TXT in domain bind. The domain names are cachesize.bind,
// insertions.bind, evictions.bind, misses.bind, hits.bind, auth.bind and
// servers.bind. An example command to query this, using the dig utility would
// be:
//     dig +short chaos txt cachesize.bind

// Config contains the configuration for the collector.
type Config struct {
	DnsClient    *dns.Client
	DnsmasqAddr  string
	LeasesPath   string
	ExposeLeases bool
}

// Collector implements prometheus.Collector and exposes dnsmasq metrics.
type Collector struct {
	cfg Config
}

type lease struct {
	expiry       uint64
	macAddress   string
	ipAddress    string
	computerName string
	clientId     string
}

// New creates a new Collector.
func New(cfg Config) *Collector {
	return &Collector{
		cfg: cfg,
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range floatMetrics {
		ch <- d
	}
	for _, d := range serversMetrics {
		ch <- d
	}
	ch <- leases
	ch <- leaseMetrics
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	var eg errgroup.Group

	eg.Go(func() error {
		questionBinds := []string{
			"cachesize.bind.",
			"insertions.bind.",
			"evictions.bind.",
			"misses.bind.",
			"hits.bind.",
			"auth.bind.",
			"servers.bind.",
		}

		for _, questionBind := range questionBinds {
			err := queryDnsmasq(questionBind, c, ch)

			if err != nil {
				return err
			}
		}

		return nil
	})

	eg.Go(func() error {
		activeLeases, err := readLeaseFile(c.cfg.LeasesPath)
		if err != nil {
			return err
		}
		ch <- prometheus.MustNewConstMetric(leases, prometheus.GaugeValue, float64(len(activeLeases)))

		if c.cfg.ExposeLeases {
			for _, activeLease := range activeLeases {
				ch <- prometheus.MustNewConstMetric(leaseMetrics, prometheus.GaugeValue, float64(activeLease.expiry),
					activeLease.macAddress, activeLease.ipAddress, activeLease.computerName, activeLease.clientId)
			}
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		log.Printf("could not complete scrape: %v", err)
	}
}

func queryDnsmasq(questionBind string, c *Collector, ch chan<- prometheus.Metric) error {
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{
			question(questionBind),
		},
	}
	in, _, err := c.cfg.DnsClient.Exchange(msg, c.cfg.DnsmasqAddr)
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
			for _, str := range txt.Txt {
				arr := strings.Fields(str)
				if got, want := len(arr), 3; got != want {
					return fmt.Errorf("stats DNS record servers.bind.: unexpeced number of argument in record: got %d, want %d", got, want)
				}
				queries, err := strconv.ParseFloat(arr[1], 64)
				if err != nil {
					return err
				}
				failedQueries, err := strconv.ParseFloat(arr[2], 64)
				if err != nil {
					return err
				}
				ch <- prometheus.MustNewConstMetric(serversMetrics["queries"], prometheus.GaugeValue, queries, arr[0])
				ch <- prometheus.MustNewConstMetric(serversMetrics["queries_failed"], prometheus.GaugeValue, failedQueries, arr[0])
			}
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
			ch <- prometheus.MustNewConstMetric(g, prometheus.GaugeValue, f)
		}
	}

	return nil
}

func question(name string) dns.Question {
	return dns.Question{
		Name:   name,
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassCHAOS,
	}
}

func parseLease(line string) (*lease, error) {
	arr := strings.Fields(line)
	if got, want := len(arr), 5; got != want {
		return nil, fmt.Errorf("illegal lease: expected %d fields, got %d", want, got)
	}

	expires, err := strconv.ParseUint(arr[0], 10, 64)
	if err != nil {
		return nil, err
	}

	return &lease{
		expiry:       expires,
		macAddress:   arr[1],
		ipAddress:    arr[2],
		computerName: arr[3],
		clientId:     arr[4],
	}, nil
}

// Read the DHCP lease file with the given path and return a list of leases.
//
// The format of the DHCP lease file written by dnsmasq is not formally
// documented in the dnsmasq manual but the format has been described in the
// mailing list:
//
// - https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2006q2/000733.html
// - https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2016q2/010595.html
//
// The DHCP lease file is written to by lease_update_file() in
// src/lease.c, and is read by lease_init().
func readLeaseFile(path string) ([]lease, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// ignore
			return []lease{}, nil
		}

		return nil, err
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)
	activeLeases := []lease{}
	for i := 1; scanner.Scan(); i++ {
		leaseLine := scanner.Text()
		if activeLease, err := parseLease(leaseLine); err == nil {
			activeLeases = append(activeLeases, *activeLease)
		} else {
			log.Printf("Error parsing lease (%d, %q): %s", i, leaseLine, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return activeLeases, nil
}
