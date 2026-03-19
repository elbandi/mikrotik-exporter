package health

import (
	"fmt"
	"strconv"

	"github.com/go-routeros/routeros/v3/proto"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
)

var (
	labelNames         = []string{"name", "address"}
	metricDescriptions = map[string]*prometheus.Desc{
		"voltage":         metrics.BuildMetricDescription(prefix, "voltage", "input voltage to routeros board in volts", labelNames),
		"temperature":     metrics.BuildMetricDescription(prefix, "board_temperature", "temperature of routeros board in degrees celsius", labelNames),
		"cpu-temperature": metrics.BuildMetricDescription(prefix, "cpu_temperature", "cpu temperature in degrees celsius", labelNames),
	}
)

const prefix = "health"

type healthCollector struct{}

func NewCollector() *healthCollector {
	return &healthCollector{}
}

func (c *healthCollector) Name() string {
	return prefix
}

func (c *healthCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d
	}
}

func (c *healthCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch system health: %w", err)
	}

	for _, re := range stats {
		if metric, ok := re.Map["name"]; ok {
			c.collectMetricForProperty(metric, re, ctx)
		} else {
			c.collectForStat(re, ctx)
		}
	}

	return nil
}

func (c *healthCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run("/system/health/print")
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *healthCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	for p := range metricDescriptions {
		c.collectMetricForProperty(p, re, ctx)
	}
}

func (c *healthCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		var ok bool
		if value, ok = re.Map["value"]; !ok {
			return
		}
	}

	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse system health metric value")
		return
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions[property], prometheus.GaugeValue, v,
		ctx.DeviceName, ctx.DeviceAddress)
}
