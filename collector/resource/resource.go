package resource

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
	properties         = []string{"free-memory", "total-memory", "cpu-load", "free-hdd-space", "total-hdd-space", "uptime", "board-name", "version"}
	labelNames         = []string{"name", "address", "boardname", "version"}
	metricDescriptions = map[string]*metrics.MetricDescription{
		"free-memory": {
			Desc:      metrics.BuildMetricDescription(prefix, "free_memory", "amount of free memory in bytes", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"total-memory": {
			Desc:      metrics.BuildMetricDescription(prefix, "total_memory", "amount of total memory in bytes", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"cpu-load": {
			Desc:      metrics.BuildMetricDescription(prefix, "cpu_load", "cpu load in percent", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"free-hdd-space": {
			Desc:      metrics.BuildMetricDescription(prefix, "free_hdd_space", "amount of free hdd space in bytes", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"total-hdd-space": {
			Desc:      metrics.BuildMetricDescription(prefix, "total_hdd_space", "amount of total hdd space in bytes", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"uptime": {
			Desc:      metrics.BuildMetricDescription(prefix, "uptime", "system uptime in seconds", labelNames),
			ValueType: prometheus.CounterValue,
		},
	}
)

const prefix = "system"

type resourceCollector struct{}

func NewCollector() *resourceCollector {
	return &resourceCollector{}
}

func (c *resourceCollector) Name() string {
	return prefix
}

func (c *resourceCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d.Desc
	}
}

func (c *resourceCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch resource metrics: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *resourceCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run("/system/resource/print", "=.proplist="+strings.Join(properties, ","))
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *resourceCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	for p := range metricDescriptions {
		c.collectMetricForProperty(p, re, ctx)
	}
}

func (c *resourceCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		return
	}

	var (
		v   float64
		err error
	)
	switch property {
	case "uptime":
		v, err = parsers.ParseDuration(value)
	default:
		v, err = strconv.ParseFloat(re.Map[property], 64)
	}

	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse system resource metric value")
		return
	}

	metric := metricDescriptions[property]
	ctx.MetricsChan <- prometheus.MustNewConstMetric(metric.Desc, metric.ValueType, v,
		ctx.DeviceName, ctx.DeviceAddress,
		re.Map["board-name"], re.Map["version"])
}
