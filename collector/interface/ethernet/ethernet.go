package ethernet

import (
	"fmt"
	"strings"

	"github.com/go-routeros/routeros/v3/proto"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
)

var (
	properties         = []string{"name", "status", "rate", "full-duplex", "comment"}
	labelNames         = []string{"name", "address", "interface", "comment"}
	metricDescriptions = map[string]*prometheus.Desc{
		"status":      metrics.BuildMetricDescription(prefix, "status", "ethernet interface status (up = 1)", labelNames),
		"rate":        metrics.BuildMetricDescription(prefix, "rate", "ethernet interface link rate in mbps", labelNames),
		"full-duplex": metrics.BuildMetricDescription(prefix, "full_duplex", "ethernet interface full duplex status (full duplex = 1)", labelNames),
	}
)

const prefix = "ethernet"

type ethernetCollector struct{}

func NewCollector() *ethernetCollector {
	return &ethernetCollector{}
}

func (c *ethernetCollector) Name() string {
	return prefix
}

func (c *ethernetCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d
	}
}

func (c *ethernetCollector) Collect(ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/ethernet/print",
		"=.proplist=name",
	)
	if err != nil {
		return fmt.Errorf("failed to fetch ethernet interface names: %w", err)
	}

	names := make([]string, 0, len(reply.Re))
	for _, re := range reply.Re {
		names = append(names, re.Map["name"])
	}

	return c.collectForInterfaces(names, ctx)
}

func (c *ethernetCollector) collectForInterfaces(interfaces []string, ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/ethernet/monitor",
		"=numbers="+strings.Join(interfaces, ","),
		"=once=",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return fmt.Errorf("failed to fetch ethernet monitor: %w", err)
	}

	for _, re := range reply.Re {
		c.collectMetricsForInterface(re, ctx)
	}

	return nil
}

func (c *ethernetCollector) collectMetricsForInterface(re *proto.Sentence, ctx *context.Context) {
	for property := range metricDescriptions {
		value := re.Map[property]
		if len(value) == 0 {
			continue
		}

		var v float64
		switch property {
		case "status":
			if value == "link-ok" {
				v = 1
			}
		case "rate":
			switch value {
			case "10Mbps":
				v = 10
			case "100Mbps":
				v = 100
			case "1Gbps":
				v = 1000
			case "10Gbps":
				v = 10000
			}
		case "full-duplex":
			if value == "true" {
				v = 1
			}
		}

		ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions[property], prometheus.GaugeValue, v,
			ctx.DeviceName, ctx.DeviceAddress, re.Map["name"], re.Map["comment"],
		)
	}
}
