package wireguard_peers

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
	properties         = []string{"interface", "current-endpoint-address", "current-endpoint-port", "allowed-address", "rx", "tx", "last-handshake"}
	labelNames         = []string{"name", "address", "interface", "current_endpoint_address", "current_endpoint_port", "allowed_address"}
	metricDescriptions = map[string]*metrics.MetricDescription{
		"last-handshake": {
			Desc:      metrics.BuildMetricDescription(prefix, "since_last_handshake", "time in seconds since wireguard peer last handshake", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"rx": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_bytes", "received bytes from wireguard peer", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"tx": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_bytes", "sent bytes to wireguard peer", labelNames),
			ValueType: prometheus.CounterValue,
		},
	}
)

const prefix = "wireguard_peers"

type wireguardPeersCollector struct{}

func NewCollector() *wireguardPeersCollector {
	return &wireguardPeersCollector{}
}

func (c *wireguardPeersCollector) Name() string {
	return prefix
}

func (c *wireguardPeersCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d.Desc
	}
}

func (c *wireguardPeersCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch wireguard peers metrics: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *wireguardPeersCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/wireguard/peers/print",
		"?disabled=false",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *wireguardPeersCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	for p := range metricDescriptions {
		c.collectMetricForProperty(p, re, ctx)
	}
}

func (c *wireguardPeersCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		return
	}

	var (
		v   float64
		err error
	)
	switch property {
	case "last-handshake":
		v, err = parsers.ParseDuration(value)
	default:
		v, err = strconv.ParseFloat(value, 64)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"interface": re.Map["interface"],
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse wireguard peer metric value")
		return
	}

	desc := metricDescriptions[property]
	ctx.MetricsChan <- prometheus.MustNewConstMetric(desc.Desc, desc.ValueType, v, ctx.DeviceName, ctx.DeviceAddress,
		re.Map["interface"],
		re.Map["current-endpoint-address"],
		re.Map["current-endpoint-port"],
		re.Map["allowed-address"],
	)
}
