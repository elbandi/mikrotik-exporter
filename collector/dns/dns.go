package dns

import (
	"fmt"
	"strings"

	"github.com/go-routeros/routeros/v3/proto"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
)

var (
	properties        = []string{"type", "name", "static"}
	metricDescription = metrics.BuildMetricDescription(prefix, "cache", "dns cache items",
		[]string{"name", "address", "type"},
	)
)

const prefix = "dns"

type dnsCollector struct{}

func NewCollector() *dnsCollector {
	return &dnsCollector{}
}

func (c *dnsCollector) Name() string {
	return prefix
}

func (c *dnsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricDescription
}

func (c *dnsCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch dns cache: %w", err)
	}
	counts := c.countForStat(stats, ctx)

	for k, v := range counts {
		ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescription, prometheus.GaugeValue, float64(v),
			ctx.DeviceName, ctx.DeviceAddress, k,
		)
	}

	return nil
}

func (c *dnsCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/ip/dns/cache/print",
		"?static=no",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *dnsCollector) countForStat(stats []*proto.Sentence, ctx *context.Context) (ret map[string]int) {
	_ = ctx
	ret = make(map[string]int, 0)
	for _, re := range stats {
		value := re.Map["type"]
		if len(value) == 0 {
			continue
		}
		ret[value] += 1
	}
	return
}
