package kid_control

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
	properties         = []string{"ip-address", "mac-address", "bytes-down", "bytes-up", "idle-time"}
	labelNames         = []string{"name", "address", "ip_address", "mac_address"}
	metricDescriptions = map[string]*metrics.MetricDescription{
		"idle-time": {
			Desc:      metrics.BuildMetricDescription(prefix, "device_since_idle", "time in seconds since last activity", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"bytes-down": {
			Desc:      metrics.BuildMetricDescription(prefix, "device_rx_bytes", "received bytes from device", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"bytes-up": {
			Desc:      metrics.BuildMetricDescription(prefix, "device_tx_bytes", "sent bytes to device", labelNames),
			ValueType: prometheus.CounterValue,
		},
	}
)

const prefix = "kid_control"

type kidControlCollector struct{}

func NewCollector() *kidControlCollector {
	return &kidControlCollector{}
}

func (c *kidControlCollector) Name() string {
	return prefix
}

func (c *kidControlCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d.Desc
	}
}

func (c *kidControlCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch kid control: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *kidControlCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/ip/kid-control/device/print",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *kidControlCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	for p := range metricDescriptions {
		c.collectMetricForProperty(p, re, ctx)
	}
}
func (c *kidControlCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		return
	}
	var (
		v   float64
		err error
	)
	switch property {
	case "idle-time":
		v, err = parsers.ParseDuration(value)
	default:
		v, err = strconv.ParseFloat(value, 64)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"router_id": re.Map["router-id"],
			"value":     value,
			"error":     err,
		}).Error("failed to parse kid_control device value")
		return
	}

	metric := metricDescriptions[property]
	ctx.MetricsChan <- prometheus.MustNewConstMetric(metric.Desc, metric.ValueType, v,
		ctx.DeviceName, ctx.DeviceAddress,
		re.Map["ip-address"], re.Map["mac-address"],
	)
}
