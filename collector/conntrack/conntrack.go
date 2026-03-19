package conntrack

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
	properties                    = []string{"total-entries", "max-entries"}
	labelNames                    = []string{"name", "address"}
	totalEntriesMetricDescription = metrics.BuildMetricDescription(prefix, "entries", "number of tracked connections", labelNames)
	maxEntriesMetricDescription   = metrics.BuildMetricDescription(prefix, "max_entries", "conntrack table capacity", labelNames)
)

const prefix = "conntrack"

type conntrackCollector struct{}

func NewCollector() *conntrackCollector {
	return &conntrackCollector{}
}

func (c *conntrackCollector) Name() string {
	return prefix
}

func (c *conntrackCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- totalEntriesMetricDescription
	ch <- maxEntriesMetricDescription
}

func (c *conntrackCollector) Collect(ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/ip/firewall/connection/tracking/print",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return fmt.Errorf("failed to fetch conntrack table metrics: %w", err)
	}

	for _, re := range reply.Re {
		c.collectMetricForProperty("total-entries", totalEntriesMetricDescription, re, ctx)
		c.collectMetricForProperty("max-entries", maxEntriesMetricDescription, re, ctx)
	}

	return nil
}

func (c *conntrackCollector) collectMetricForProperty(property string, desc *prometheus.Desc, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		return
	}

	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse conntrack metric value")
		return
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v, ctx.DeviceName, ctx.DeviceAddress)
}
