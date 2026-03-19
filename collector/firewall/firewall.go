package firewall

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-routeros/routeros/v3/proto"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
)

var (
	tables = map[string][]string{
		"filter": []string{"disabled", "src-address", "dst-address", "src-address-list", "dst-address-list", "protocol", "src-port", "dst-port", "port", "in-interface", "out-interface", "in-interface-list", "out-interface-list", "packet-mark", "connection-mark", "routing-mark", "connection-type", "connection-state", "connection-nat-state", "layer7-protocol", "content", "connection-bytes", "connection-rate", "per-connection-classifier", "src-mac-address", "out-bridge-port", "in-bridge-port", "in-bridge-port-list", "out-bridge-port-list", "ipsec-policy", "tls-host", "ingress-priority", "priority", "dscp", "tcp-mss", "packet-size", "random", "tcp-flags", "icmp-options", "ipv4-options", "ttl", "nth", "connection-limit", "src-address-type", "dst-address-type", "hotspot", "fragment", "limit", "dst-limit", "time", "psd", "action", "log", "log-prefix", "address-list", "address-list-timeout", "jump-target", "reject-with"},
		"nat":    []string{"disabled", "src-address", "dst-address", "src-address-list", "dst-address-list", "protocol", "src-port", "dst-port", "port", "in-interface", "out-interface", "in-interface-list", "out-interface-list", "packet-mark", "connection-mark", "routing-mark", "connection-type", "layer7-protocol", "content", "connection-bytes", "connection-rate", "per-connection-classifier", "src-mac-address", "out-bridge-port", "in-bridge-port", "in-bridge-port-list", "out-bridge-port-list", "ipsec-policy", "tls-host", "ingress-priority", "priority", "dscp", "tcp-mss", "packet-size", "random", "icmp-options", "ipv4-options", "ttl", "nth", "connection-limit", "src-address-type", "dst-address-type", "hotspot", "fragment", "limit", "dst-limit", "time", "psd", "action", "log", "log-prefix", "address-list", "address-list-timeout", "to-addresses", "to-ports", "jump-target", "same-not-by-dst"},
		"mangle": []string{"disabled", "src-address", "dst-address", "src-address-list", "dst-address-list", "protocol", "src-port", "dst-port", "port", "in-interface", "out-interface", "in-interface-list", "out-interface-list", "packet-mark", "connection-mark", "routing-mark", "connection-type", "connection-state", "connection-nat-state", "layer7-protocol", "content", "connection-bytes", "connection-rate", "per-connection-classifier", "src-mac-address", "out-bridge-port", "in-bridge-port", "in-bridge-port-list", "out-bridge-port-list", "ipsec-policy", "tls-host", "ingress-priority", "priority", "dscp", "tcp-mss", "packet-size", "random", "tcp-flags", "icmp-options", "ipv4-options", "ttl", "nth", "connection-limit", "src-address-type", "dst-address-type", "hotspot", "fragment", "limit", "dst-limit", "time", "psd", "action", "log", "log-prefix", "address-list", "address-list-timeout", "new-dscp", "passthrough", "new-mss", "new-ttl", "jump-target", "new-connection-mark", "new-packet-mark", "new-routing-mark", "route-dst", "new-priority", "sniff-target", "sniff-target-port", "sniff-id"},
		"raw":    []string{"disabled", "src-address", "dst-address", "src-address-list", "dst-address-list", "protocol", "src-port", "dst-port", "port", "in-interface", "out-interface", "in-interface-list", "out-interface-list", "packet-mark", "content", "per-connection-classifier", "src-mac-address", "out-bridge-port", "in-bridge-port", "in-bridge-port-list", "out-bridge-port-list", "ipsec-policy", "tls-host", "ingress-priority", "priority", "dscp", "tcp-mss", "packet-size", "random", "tcp-flags", "icmp-options", "ipv4-options", "ttl", "nth", "src-address-type", "dst-address-type", "hotspot", "fragment", "limit", "dst-limit", "time", "psd", "action", "log", "log-prefix", "address-list", "address-list-timeout", "jump-target"},
	}
	labelNames             = []string{"name", "address", "table", "chain", "rule"}
	ruleMetricDescriptions = map[string]*prometheus.Desc{
		"bytes":   metrics.BuildMetricDescription(prefix, "bytes", "number of bytes", labelNames),
		"packets": metrics.BuildMetricDescription(prefix, "packets", "number of packets", labelNames),
	}
)

const prefix = "firewall"

type firewallCollector struct{}

func NewCollector() *firewallCollector {
	return &firewallCollector{}
}

func (c *firewallCollector) Name() string {
	return prefix
}

func (c *firewallCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range ruleMetricDescriptions {
		ch <- d
	}
}

func (c *firewallCollector) Collect(ctx *context.Context) error {
	eg := errgroup.Group{}
	for i := range tables {
		table := i
		eg.Go(func() error {
			return c.collectForTable(table, ctx)
		})
	}

	return eg.Wait()
}

func (c *firewallCollector) collectForTable(table string, ctx *context.Context) error {
	eg := errgroup.Group{}
	eg.Go(func() error {
		stats, err := c.fetchRules(table, ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch firewall rules: %w", err)
		}

		for _, re := range stats {
			c.collectRuleStats(table, re, ctx)
		}

		return nil
	})

	return eg.Wait()
}

func (c *firewallCollector) fetchRules(table string, ctx *context.Context) ([]*proto.Sentence, error) {
	properties := append(append([]string{"chain"}, tables[table]...), "bytes", "packets")
	reply, err := ctx.RouterOSClient.Run(
		fmt.Sprintf("/ip/firewall/%s/print", table),
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *firewallCollector) collectRuleStats(table string, re *proto.Sentence, ctx *context.Context) {
	for p := range ruleMetricDescriptions {
		c.collectRuleMetricForProperty(table, p, re, ctx)
	}
}

func (c *firewallCollector) collectRuleMetricForProperty(table string, property string, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		return
	}

	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse firewall rule metric value")
		return
	}

	var rule []string
	for _, p := range tables[table] {
		val, ok := re.Map[p]
		if ok && len(val) > 0 {
			if !(p == "disabled" && val == "false") {
				rule = append(rule, p+"="+val)
			}
		}
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(ruleMetricDescriptions[property], prometheus.CounterValue, v,
		ctx.DeviceName, ctx.DeviceAddress,
		table, re.Map["chain"], strings.Join(rule, " "))
}
