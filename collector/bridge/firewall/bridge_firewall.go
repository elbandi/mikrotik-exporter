package bridge_firewall

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
		"filter": []string{"disabled", "in-interface", "out-interface", "in-interface-list", "out-interface-list", "in-bridge", "out-bridge", "in-bridge-list", "out-bridge-list", "src-mac-address", "dst-mac-address", "mac-protocol", "src-address", "src-port", "dst-address", "dst-port", "ip-protocol", "tls-host", "packet-mark", "ingress-priority", "vlan-id", "vlan-priority", "vlan-encap", "802.3-sap", "802.3-type", "packet-type", "limit", "arp-opcode", "arp-hardware-type", "arp-packet-type", "arp-src-address", "arp-dst-address", "arp-src-mac-address", "arp-dst-mac-address", "arp-gratuitous", "stp-type", "stp-flags", "stp-root-address", "stp-root-cost", "stp-sender-address", "stp-port", "stp-root-priority", "stp-sender-priority", "stp-msg-age", "stp-max-age", "stp-hello-time", "stp-forward-delay", "action", "log", "log-prefix", "jump-target", "new-packet-mark", "new-priority", "passthrough"},
		"nat":    []string{"disabled", "in-interface", "out-interface", "in-interface-list", "out-interface-list", "in-bridge", "out-bridge", "in-bridge-list", "out-bridge-list", "src-mac-address", "dst-mac-address", "mac-protocol", "src-address", "src-port", "dst-address", "dst-port", "ip-protocol", "tls-host", "packet-mark", "ingress-priority", "vlan-id", "vlan-priority", "vlan-encap", "802.3-sap", "802.3-type", "packet-type", "limit", "arp-opcode", "arp-hardware-type", "arp-packet-type", "arp-src-address", "arp-dst-address", "arp-src-mac-address", "arp-dst-mac-address", "arp-gratuitous", "stp-type", "stp-flags", "stp-root-address", "stp-root-cost", "stp-sender-address", "stp-port", "stp-root-priority", "stp-sender-priority", "stp-msg-age", "stp-max-age", "stp-hello-time", "stp-forward-delay", "action", "log", "log-prefix", "to-arp-reply-mac-address", "to-dst-mac-address", "jump-target", "new-packet-mark", "new-priority", "passthrough", "to-src-mac-address"},
	}
	labelNames             = []string{"name", "address", "table", "chain", "rule"}
	ruleMetricDescriptions = map[string]*prometheus.Desc{
		"bytes":   metrics.BuildMetricDescription(prefix, "bytes", "number of bytes", labelNames),
		"packets": metrics.BuildMetricDescription(prefix, "packets", "number of packets", labelNames),
	}
)

const prefix = "bridge_firewall"

type bridgeFirewallCollector struct{}

func NewCollector() *bridgeFirewallCollector {
	return &bridgeFirewallCollector{}
}

func (c *bridgeFirewallCollector) Name() string {
	return prefix
}

func (c *bridgeFirewallCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range ruleMetricDescriptions {
		ch <- d
	}
}

func (c *bridgeFirewallCollector) Collect(ctx *context.Context) error {
	eg := errgroup.Group{}
	for i := range tables {
		table := i
		eg.Go(func() error {
			return c.collectForTable(table, ctx)
		})
	}

	return eg.Wait()
}

func (c *bridgeFirewallCollector) collectForTable(table string, ctx *context.Context) error {
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

func (c *bridgeFirewallCollector) fetchRules(table string, ctx *context.Context) ([]*proto.Sentence, error) {
	properties := append(append([]string{"chain"}, tables[table]...), "bytes", "packets")
	reply, err := ctx.RouterOSClient.Run(
		fmt.Sprintf("/interface/bridge/%s/print", table),
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *bridgeFirewallCollector) collectRuleStats(table string, re *proto.Sentence, ctx *context.Context) {
	for p := range ruleMetricDescriptions {
		c.collectRuleMetricForProperty(table, p, re, ctx)
	}
}

func (c *bridgeFirewallCollector) collectRuleMetricForProperty(table string, property string, re *proto.Sentence, ctx *context.Context) {
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
