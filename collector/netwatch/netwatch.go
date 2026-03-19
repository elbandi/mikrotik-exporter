package netwatch

import (
	"fmt"
	"strings"

	"github.com/go-routeros/routeros/v3/proto"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
)

var (
	properties        = []string{"host", "comment", "status"}
	metricDescription = metrics.BuildMetricDescription(prefix, "status", "netwatch status (up = 1, down = -1)",
		[]string{"name", "address", "host", "comment"},
	)
)

const prefix = "netwatch"

type netwatchCollector struct{}

func NewCollector() *netwatchCollector {
	return &netwatchCollector{}
}

func (c *netwatchCollector) Name() string {
	return prefix
}

func (c *netwatchCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricDescription
}

func (c *netwatchCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch netwatch: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *netwatchCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/tool/netwatch/print",
		"?disabled=false",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *netwatchCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	value := re.Map["status"]
	if len(value) == 0 {
		return
	}

	var v float64
	switch value {
	case "up":
		v = 1
	case "down":
		v = -1
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescription, prometheus.GaugeValue, v,
		ctx.DeviceName, ctx.DeviceAddress, re.Map["host"], re.Map["comment"],
	)
}
