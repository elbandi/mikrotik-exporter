package capsman

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
	properties         = []string{"interface", "mac-address", "ssid", "uptime", "tx-signal", "rx-signal", "packets", "bytes"}
	metricProperties   = []string{"uptime", "tx-signal", "rx-signal", "packets", "bytes"}
	labelNames         = []string{"name", "address", "interface", "mac_address", "ssid"}
	metricDescriptions = map[string]metrics.MetricDescription{
		"uptime": {
			Desc:      metrics.BuildMetricDescription(prefix, "uptime", "capsman client uptime in seconds", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"tx-signal": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_signal", "capsman client tx signal strength in dbm", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"rx-signal": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_signal", "capsman client rx signal strength in dbm", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"tx-packets": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_packets", "capsman client tx packets count", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"tx-bytes": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_bytes", "capsman client tx bytes count", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"rx-packets": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_packets", "capsman client rx packets count", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"rx-bytes": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_bytes", "capsman client rx bytes count", labelNames),
			ValueType: prometheus.CounterValue,
		},
	}
)

const prefix = "capsman_client"

type capsmanCollector struct{}

func NewCollector() *capsmanCollector {
	return &capsmanCollector{}
}

func (c *capsmanCollector) Name() string {
	return prefix
}

func (c *capsmanCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d.Desc
	}
}

func (c *capsmanCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch capsman station metrics: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *capsmanCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/caps-man/registration-table/print",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *capsmanCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	for _, p := range metricProperties {
		c.collectMetricForProperty(p, re, ctx)
	}
}

func (c *capsmanCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		return
	}

	var (
		v   float64
		err error
	)
	switch property {
	case "packets", "bytes":
		tx, rx, propErr := parsers.ParseCommaSeparatedValuesToFloat64(value)
		switch propErr != nil {
		case true:
			err = propErr
		case false:
			ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions["tx-"+property].Desc, metricDescriptions["tx-"+property].ValueType, tx,
				ctx.DeviceName, ctx.DeviceAddress,
				re.Map["interface"], re.Map["mac-address"], re.Map["ssid"],
			)
			ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions["rx-"+property].Desc, metricDescriptions["rx-"+property].ValueType, rx,
				ctx.DeviceName, ctx.DeviceAddress,
				re.Map["interface"], re.Map["mac-address"], re.Map["ssid"],
			)
			return
		}
	case "uptime":
		v, err = parsers.ParseDuration(value)
	default:
		v, err = strconv.ParseFloat(value, 64)
	}

	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse capsman station metric value")
		return
	}

	metric := metricDescriptions[property]
	ctx.MetricsChan <- prometheus.MustNewConstMetric(metric.Desc, metric.ValueType, v,
		ctx.DeviceName, ctx.DeviceAddress,
		re.Map["interface"], re.Map["mac-address"], re.Map["ssid"],
	)
}
