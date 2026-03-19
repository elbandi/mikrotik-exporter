package w60g

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
	properties         = []string{"name", "signal", "rssi", "tx-mcs", "frequency", "tx-phy-rate", "tx-sector", "distance", "tx-packet-error-rate"}
	labelNames         = []string{"name", "address", "interface"}
	metricDescriptions = map[string]*prometheus.Desc{
		"signal":               metrics.BuildMetricDescription(prefix, "signal", "w60g interface signal quality in percent", labelNames),
		"rssi":                 metrics.BuildMetricDescription(prefix, "rssi", "w60g interface received signal strength indicator in db", labelNames),
		"tx-mcs":               metrics.BuildMetricDescription(prefix, "tx_mcs", "w60g interface tx mcs", labelNames),
		"tx-phy-rate":          metrics.BuildMetricDescription(prefix, "tx_phy_rate", "w60g interface phy rate in mbps", labelNames),
		"frequency":            metrics.BuildMetricDescription(prefix, "frequency", "w60g interface tx frequency in mhz", labelNames),
		"tx-sector":            metrics.BuildMetricDescription(prefix, "tx_sector", "w60g interface tx sector", labelNames),
		"distance":             metrics.BuildMetricDescription(prefix, "tx_distance", "w60g interface tx distance in meters", labelNames),
		"tx-packet-error-rate": metrics.BuildMetricDescription(prefix, "tx_packet_error_rate", "w60g interface tx packet error rate", labelNames),
	}
)

const prefix = "w60g_interface"

type w60gInterfaceCollector struct{}

func NewCollector() *w60gInterfaceCollector {
	return &w60gInterfaceCollector{}
}

func (c *w60gInterfaceCollector) Name() string {
	return prefix
}

func (c *w60gInterfaceCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d
	}
}

func (c *w60gInterfaceCollector) Collect(ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/w60g/print",
		"=.proplist=name",
	)
	if err != nil {
		return fmt.Errorf("failed to fetch w60g interfaces: %w", err)
	}

	interfaces := make([]string, 0, len(reply.Re))
	for _, re := range reply.Re {
		interfaces = append(interfaces, re.Map["name"])
	}

	return c.collectw60gMetricsForInterfaces(interfaces, ctx)
}
func (c *w60gInterfaceCollector) collectw60gMetricsForInterfaces(interfaces []string, ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/w60g/monitor",
		"=numbers="+strings.Join(interfaces, ","),
		"=once=",
		"=.proplist="+strings.Join(properties, ","))
	if err != nil {
		return fmt.Errorf("failed to fetch w60g monitor info")
	}

	for _, re := range reply.Re {
		c.collectMetricsForInterface(re, ctx)
	}

	return nil
}

func (c *w60gInterfaceCollector) collectMetricsForInterface(re *proto.Sentence, ctx *context.Context) {
	for property := range metricDescriptions {
		value := re.Map[property]
		if len(value) == 0 {
			continue
		}

		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			log.WithFields(log.Fields{
				"collector": c.Name(),
				"device":    ctx.DeviceName,
				"interface": re.Map["name"],
				"property":  property,
				"error":     err,
			}).Error("failed to parse w60g interface metric value")
			return
		}

		ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions[property], prometheus.GaugeValue, v,
			ctx.DeviceName, ctx.DeviceAddress, re.Map["name"],
		)
	}
}
