package poe

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-routeros/routeros/v3/proto"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
)

var (
	properties         = []string{"name", "poe-out-current", "poe-out-voltage", "poe-out-power"}
	labelNames         = []string{"name", "address", "interface"}
	metricDescriptions = map[string]*prometheus.Desc{
		"poe-out-current": metrics.BuildMetricDescription(prefix, "current", "poe current in milliamps", labelNames),
		"poe-out-voltage": metrics.BuildMetricDescription(prefix, "voltage", "poe voltage in volts", labelNames),
		"poe-out-power":   metrics.BuildMetricDescription(prefix, "power", "poe power in watts", labelNames),
	}
)

const prefix = "poe"

type poeCollector struct{}

func NewCollector() *poeCollector {
	return &poeCollector{}
}

func (c *poeCollector) Name() string {
	return prefix
}

func (c *poeCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d
	}
}

func (c *poeCollector) Collect(ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/ethernet/poe/print",
		"=.proplist=name",
	)
	if err != nil {
		return fmt.Errorf("failed to fetch poe interface names: %w", err)
	}

	interfaces := make([]string, 0, len(reply.Re))
	for _, re := range reply.Re {
		interfaces = append(interfaces, re.Map["name"])
	}

	return c.collectMetricsForInterfaces(interfaces, ctx)
}

func (c *poeCollector) collectMetricsForInterfaces(interfaces []string, ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/ethernet/poe/monitor",
		"=numbers="+strings.Join(interfaces, ","),
		"=once=",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return fmt.Errorf("failed to fetch poe monitor: %w", err)
	}

	for _, re := range reply.Re {
		c.collectMetricsForInterface(re, ctx)
	}

	return nil
}

func (c *poeCollector) collectMetricsForInterface(re *proto.Sentence, ctx *context.Context) {
	for property := range metricDescriptions {
		value := re.Map[property]
		if len(value) == 0 {
			return
		}

		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			log.WithFields(log.Fields{
				"device":    ctx.DeviceName,
				"interface": re.Map["name"],
				"property":  property,
				"error":     err,
			}).Error("failed to parse poe ethernet metric")
			continue
		}

		ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions[property], prometheus.GaugeValue, v,
			ctx.DeviceName, ctx.DeviceAddress, re.Map["name"])
	}
}
