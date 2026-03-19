package _interface

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
	properties         = []string{"name", "type", "disabled", "comment", "running", "slave", "actual-mtu", "rx-byte", "tx-byte", "rx-packet", "tx-packet", "rx-error", "tx-error", "rx-drop", "tx-drop", "link-downs"}
	labelNames         = []string{"name", "address", "interface", "type", "disabled", "comment", "running", "slave"}
	metricDescriptions = map[string]*metrics.MetricDescription{
		"actual-mtu": {
			Desc:      metrics.BuildMetricDescription(prefix, "actual_mtu", "actual mtu of interface", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"rx-byte": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_byte", "number of rx bytes on interface", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"tx-byte": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_byte", "number of tx bytes on interface", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"rx-packet": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_packet", "number of rx packets on interface", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"tx-packet": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_packet", "number of tx packets on interface", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"rx-error": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_error", "number of rx errors on interface", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"tx-error": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_error", "number of tx errors on interface", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"rx-drop": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_drop", "number of dropped rx packets on interface", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"tx-drop": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_drop", "number of dropped tx packets on interface", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"link-downs": {
			Desc:      metrics.BuildMetricDescription(prefix, "link_downs", "number of times link has gone down on interface", labelNames),
			ValueType: prometheus.CounterValue,
		},
	}
)

const prefix = "interface"

type interfaceCollector struct{}

func NewCollector() *interfaceCollector {
	return &interfaceCollector{}
}

func (c *interfaceCollector) Name() string {
	return prefix
}

func (c *interfaceCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d.Desc
	}
}

func (c *interfaceCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch interface metrics: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *interfaceCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/print",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *interfaceCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	for p := range metricDescriptions {
		c.collectMetricForProperty(p, re, ctx)
	}
}

func (c *interfaceCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		return
	}

	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"interface": re.Map["name"],
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse interface metric value")
		return
	}

	metric := metricDescriptions[property]
	ctx.MetricsChan <- prometheus.MustNewConstMetric(metric.Desc, metric.ValueType, v,
		ctx.DeviceName, ctx.DeviceAddress,
		re.Map["name"], re.Map["type"], re.Map["disabled"], re.Map["comment"], re.Map["running"], re.Map["slave"])
}
