# dnsmasq exporter

[![Build Status](https://travis-ci.org/google/dnsmasq_exporter.svg?branch=master)](https://travis-ci.org/google/dnsmasq_exporter)

dnsmasq_exporter is an exporter for [Prometheus](https://prometheus.io/),
allowing you to monitor/alert on the number of DHCP leases and various DNS
statistics.

The minimum required version of dnsmasq is 2.69, which added support for
querying the statistics via DNS.

See also the “cache statistics” section in
https://manpages.debian.org/stretch/dnsmasq-base/dnsmasq.8.en.html#NOTES

This is not an official Google product.

## Installation

``` shell
go get -u github.com/google/dnsmasq_exporter
```

## Usage

Place `dnsmasq_exporter.service` in
`/etc/systemd/system/dnsmasq_exporter.service`, then enable and start the
service using:

```shell
systemctl daemon-reload
systemctl enable --now dnsmasq_exporter
```

### Alternative usage
```shell
docker build -t dnsmasq_exporter .
docker run --restart=unless-stopped --net=host dnsmasq_exporter
```

Then, add the endpoint to your Prometheus configuration file:

```yaml
scrape_configs:
  - job_name: dnsmasq
    static_configs:
      - targets: ['localhost:9153']
```
