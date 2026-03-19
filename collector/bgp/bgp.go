package bgp

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
	properties         = []string{"name", "remote.as", "remote.address", "established", "remote.messages", "local.messages", "remote.bytes", "local.bytes"}
	labelNames         = []string{"name", "address", "session", "asn", "remote_address"}
	metricDescriptions = map[string]*metrics.MetricDescription{
		"established": {
			Desc:      metrics.BuildMetricDescription(prefix, "established", "bgp session established (up = 1)", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"remote.messages": {
			Desc:      metrics.BuildMetricDescription(prefix, "remote_messages", "number of bgp messages received per session", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"local.messages": {
			Desc:      metrics.BuildMetricDescription(prefix, "local_messages", "number of bgp messages sent per session", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"remote.bytes": {
			Desc:      metrics.BuildMetricDescription(prefix, "remote_bytes", "number of bytes received per session", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"local.bytes": {
			Desc:      metrics.BuildMetricDescription(prefix, "local_bytes", "number of bytes sent per session", labelNames),
			ValueType: prometheus.CounterValue,
		},
	}
)

const prefix = "bgp_session"

type bgpCollector struct{}

func NewCollector() *bgpCollector {
	return &bgpCollector{}
}

func (c *bgpCollector) Name() string {
	return prefix
}

func (c *bgpCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d.Desc
	}
}

func (c *bgpCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch bgp metrics: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *bgpCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/routing/bgp/session/print",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *bgpCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	for p := range metricDescriptions {
		c.collectMetricForProperty(p, re, ctx)
	}
}

func (c *bgpCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		return
	}

	session := re.Map["name"]

	var (
		v   float64
		err error
	)
	switch property {
	case "established":
		if value == "true" {
			v = 1
		}
	default:
		v, err = strconv.ParseFloat(value, 64)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"session":   session,
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse bgp metric value")
		return
	}

	desc := metricDescriptions[property]
	ctx.MetricsChan <- prometheus.MustNewConstMetric(desc.Desc, desc.ValueType, v, ctx.DeviceName, ctx.DeviceAddress, session, re.Map["remote.as"], re.Map["remote.address"])
}
