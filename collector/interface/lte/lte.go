package lte

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
	properties         = []string{"current-cellid", "primary-band", "ca-band", "rssi", "rsrp", "rsrq", "sinr"}
	labelNames         = []string{"name", "address", "interface", "cell_id", "primary_band", "ca_band"}
	metricDescriptions = map[string]*prometheus.Desc{
		"rssi": metrics.BuildMetricDescription(prefix, "rssi", "lte interface received signal strength indicator", labelNames),
		"rsrp": metrics.BuildMetricDescription(prefix, "rsrp", "lte interface reference signal received power", labelNames),
		"rsrq": metrics.BuildMetricDescription(prefix, "rsrq", "lte interface reference signal received quality", labelNames),
		"sinr": metrics.BuildMetricDescription(prefix, "sinr", "lte interface signal interference to noise ratio", labelNames),
	}
)

const prefix = "lte"

type lteCollector struct{}

func NewCollector() *lteCollector {
	return &lteCollector{}
}

func (c *lteCollector) Name() string {
	return prefix
}

func (c *lteCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d
	}
}

func (c *lteCollector) Collect(ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/lte/print",
		"?disabled=false",
		"=.proplist=name",
	)
	if err != nil {
		return fmt.Errorf("failed to fetch lte interface names: %w", err)
	}

	names := make([]string, 0, len(reply.Re))
	for _, re := range reply.Re {
		names = append(names, re.Map["name"])
	}

	return c.collectForInterfaces(names, ctx)
}

func (c *lteCollector) collectForInterfaces(interfaces []string, ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/lte/info",
		"=numbers="+strings.Join(interfaces, ","),
		"=once=",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return fmt.Errorf("failed to fetch lte interface info: %w", err)
	}

	for i, re := range reply.Re {
		c.collectMetricsForInterface(interfaces[i], re, ctx)
	}

	return nil
}

func (c *lteCollector) collectMetricsForInterface(iface string, re *proto.Sentence, ctx *context.Context) {
	for property := range metricDescriptions {
		value := re.Map[property]
		if len(value) == 0 {
			return
		}

		v, err := strconv.ParseFloat(re.Map[property], 64)
		if err != nil {
			log.WithFields(log.Fields{
				"collector": c.Name(),
				"property":  property,
				"interface": iface,
				"device":    ctx.DeviceName,
				"error":     err,
			}).Error("failed to parse interface metric value")
			continue
		}

		// get only band and its width, drop earfcn and phy-cellid info
		primaryBand := re.Map["primary-band"]
		if len(primaryBand) != 0 {
			primaryBand = strings.Fields(primaryBand)[0]
		}

		caBand := re.Map["ca-band"]
		if len(caBand) != 0 {
			caBand = strings.Fields(caBand)[0]
		}

		ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions[property], prometheus.GaugeValue, v,
			ctx.DeviceName, ctx.DeviceAddress,
			iface, re.Map["current-cellid"], primaryBand, caBand,
		)
	}
}
