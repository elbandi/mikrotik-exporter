package sfp

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
	properties         = []string{"name", "sfp-rx-loss", "sfp-tx-fault", "sfp-temperature", "sfp-supply-voltage", "sfp-tx-bias-current", "sfp-tx-power", "sfp-rx-power"}
	labelNames         = []string{"name", "address", "interface"}
	metricDescriptions = map[string]*prometheus.Desc{
		"sfp-rx-loss":         metrics.BuildMetricDescription(prefix, "rx_status", "sfp rx status (no loss = 1)", labelNames),
		"sfp-tx-fault":        metrics.BuildMetricDescription(prefix, "tx_status", "sfp tx status (no faults = 1)", labelNames),
		"sfp-temperature":     metrics.BuildMetricDescription(prefix, "temperature", "sfp temperature in degrees celsius", labelNames),
		"sfp-supply-voltage":  metrics.BuildMetricDescription(prefix, "voltage", "sfp voltage in volts", labelNames),
		"sfp-tx-bias-current": metrics.BuildMetricDescription(prefix, "tx_bias", "sfp bias in milliamps", labelNames),
		"sfp-tx-power":        metrics.BuildMetricDescription(prefix, "tx_power", "sfp tx power in dbm", labelNames),
		"sfp-rx-power":        metrics.BuildMetricDescription(prefix, "rx_power", "sfp rx power in dbm", labelNames),
	}
)

const prefix = "sfp"

type sfpCollector struct{}

func NewCollector() *sfpCollector {
	return &sfpCollector{}
}

func (c *sfpCollector) Name() string {
	return prefix
}

func (c *sfpCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d
	}
}

func (c *sfpCollector) Collect(ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/ethernet/print",
		"=.proplist=name",
	)
	if err != nil {
		return fmt.Errorf("failed to fetch sfp interface names: %w", err)
	}

	interfaces := make([]string, 0, len(reply.Re))
	for _, re := range reply.Re {
		name := re.Map["name"]
		if strings.HasPrefix(name, "sfp") {
			interfaces = append(interfaces, name)
		}
	}

	return c.collectForInterfaces(interfaces, ctx)
}

func (c *sfpCollector) collectForInterfaces(interfaces []string, ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/ethernet/monitor",
		"=numbers="+strings.Join(interfaces, ","),
		"=once=",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return fmt.Errorf("failed to fetch sfp monitor info: %w", err)
	}

	for _, re := range reply.Re {
		c.collectMetricsForInterface(re, ctx)
	}

	return nil
}

func (c *sfpCollector) collectMetricsForInterface(re *proto.Sentence, ctx *context.Context) {
	for property := range metricDescriptions {
		value := re.Map[property]
		if len(value) == 0 {
			continue
		}

		var (
			v   float64
			err error
		)
		switch property {
		case "sfp-rx-loss", "sfp-tx-fault":
			if value != "true" {
				v = 1
			}
		default:
			v, err = strconv.ParseFloat(value, 64)
		}
		if err != nil {
			log.WithFields(log.Fields{
				"collector": c.Name(),
				"device":    ctx.DeviceName,
				"interface": re.Map["name"],
				"property":  property,
				"error":     err,
			}).Error("failed to parse sfp interface metric")
			continue
		}

		ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions[property], prometheus.GaugeValue, v,
			ctx.DeviceName, ctx.DeviceAddress, re.Map["name"],
		)
	}
}
