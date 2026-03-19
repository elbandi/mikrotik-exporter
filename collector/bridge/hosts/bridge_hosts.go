package bridge_hosts

import (
	"fmt"
	"strings"

	"github.com/go-routeros/routeros/v3/proto"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
)

var (
	properties        = []string{"bridge", "mac-address", "on-interface", "dynamic", "local", "external"}
	metricDescription = metrics.BuildMetricDescription(prefix, "status", "bridge host status",
		[]string{"name", "address", "bridge", "mac_address", "on_interface", "dynamic", "local", "external"},
	)
)

const prefix = "bridge_host"

type bridgeHostsCollector struct{}

func NewCollector() *bridgeHostsCollector {
	return &bridgeHostsCollector{}
}

func (c *bridgeHostsCollector) Name() string {
	return prefix
}

func (c *bridgeHostsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricDescription
}

func (c *bridgeHostsCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch bridge hosts metrics: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *bridgeHostsCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/bridge/host/print",
		"?disabled=false",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *bridgeHostsCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescription, prometheus.GaugeValue, 1.0,
		ctx.DeviceName, ctx.DeviceAddress,
		re.Map["bridge"], re.Map["mac-address"], re.Map["on-interface"], re.Map["dynamic"],
		re.Map["local"], re.Map["external"],
	)
}
