package dhcp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-routeros/routeros/v3/proto"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
	"github.com/ogi4i/mikrotik-exporter/parsers"
)

var (
	properties        = []string{"active-mac-address", "server", "status", "expires-after", "active-address", "host-name"}
	metricDescription = metrics.BuildMetricDescription(prefix, "expires_after", "dhcp lease expires after seconds",
		[]string{"name", "address", "active_mac_address", "server", "status", "active_address", "hostname"},
	)
)

const prefix = "dhcp_lease"

type dhcpLeaseCollector struct{}

func NewCollector() *dhcpLeaseCollector {
	return &dhcpLeaseCollector{}
}

func (c *dhcpLeaseCollector) Name() string {
	return prefix
}

func (c *dhcpLeaseCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricDescription
}

func (c *dhcpLeaseCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch dhcp leases: %w", err)
	}

	for _, re := range stats {
		c.collectMetric(ctx, re)
	}

	return nil
}

func (c *dhcpLeaseCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/ip/dhcp-server/lease/print",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *dhcpLeaseCollector) collectMetric(ctx *context.Context, re *proto.Sentence) {
	value := re.Map["expires-after"]
	if len(value) == 0 {
		return
	}

	v, err := parsers.ParseDuration(value)
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"property":  "expires-after",
			"value":     value,
			"error":     err,
		}).Error("error parsing duration metric value")
		return
	}

	metric, err := prometheus.NewConstMetric(metricDescription, prometheus.GaugeValue, v, ctx.DeviceName, ctx.DeviceAddress,
		re.Map["active-mac-address"],
		re.Map["server"],
		re.Map["status"],
		re.Map["active-address"],
		strconv.QuoteToASCII(re.Map["host-name"]), // QuoteToASCII because of broken DHCP clients
	)
	if err != nil {
		log.WithFields(log.Fields{
			"device": ctx.DeviceName,
			"error":  err,
		}).Error("error parsing dhcp lease")
		return
	}
	ctx.MetricsChan <- metric
}
