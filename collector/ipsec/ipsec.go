package ipsec

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-routeros/routeros/v3/proto"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
	"github.com/ogi4i/mikrotik-exporter/parsers"
)

var (
	tunnelProperties       = []string{"src-address", "dst-address", "ph2-state", "invalid", "active", "comment"}
	peersProperties        = []string{"local-address", "remote-address", "state", "side", "uptime", "rx-bytes", "rx-packets", "tx-bytes", "tx-packets"}
	peerLabelNames         = []string{"name", "address", "local_address", "remote_address", "state", "side"}
	peerMetricDescriptions = map[string]*prometheus.Desc{
		"uptime":     metrics.BuildMetricDescription(prefix, "peer_uptime", "ipsec peer uptime in seconds", peerLabelNames),
		"rx-bytes":   metrics.BuildMetricDescription(prefix, "peer_rx_bytes", "number of ipsec peer rx bytes", peerLabelNames),
		"rx-packets": metrics.BuildMetricDescription(prefix, "peer_rx_packets", "number of ipsec peer rx packets", peerLabelNames),
		"tx-bytes":   metrics.BuildMetricDescription(prefix, "peer_tx_bytes", "number of ipsec peer tx bytes", peerLabelNames),
		"tx-packets": metrics.BuildMetricDescription(prefix, "peer_tx_packets", "number of ipsec peer tx packets", peerLabelNames),
	}
	activeTunnelsMetricDescription = metrics.BuildMetricDescription(prefix, "tunnel_active", "active ipsec tunnels (active = 1)",
		[]string{"name", "address", "src_address", "dst_address", "ph2_state", "invalid", "comment"},
	)
)

const prefix = "ipsec"

type ipsecCollector struct{}

func NewCollector() *ipsecCollector {
	return &ipsecCollector{}
}

func (c *ipsecCollector) Name() string {
	return prefix
}

func (c *ipsecCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- activeTunnelsMetricDescription
	for _, d := range peerMetricDescriptions {
		ch <- d
	}
}

func (c *ipsecCollector) Collect(ctx *context.Context) error {
	eg := errgroup.Group{}
	eg.Go(func() error {
		stats, err := c.fetchTunnels(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch ipsec tunnels: %w", err)
		}

		for _, re := range stats {
			c.collectTunnelStats(re, ctx)
		}

		return nil
	})

	eg.Go(func() error {
		stats, err := c.fetchPeers(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch ipsec peers: %w", err)
		}

		for _, re := range stats {
			c.collectPeerStats(re, ctx)
		}

		return nil
	})

	return eg.Wait()
}

func (c *ipsecCollector) fetchTunnels(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/ip/ipsec/policy/print",
		"?disabled=false",
		"?dynamic=false",
		"=.proplist="+strings.Join(tunnelProperties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *ipsecCollector) fetchPeers(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/ip/ipsec/active-peers/print",
		"=.proplist="+strings.Join(peersProperties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *ipsecCollector) collectTunnelStats(re *proto.Sentence, ctx *context.Context) {
	value := re.Map["active"]
	if len(value) == 0 {
		return
	}

	var v float64
	if value == "true" {
		v = 1
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(activeTunnelsMetricDescription, prometheus.GaugeValue, v,
		ctx.DeviceName, ctx.DeviceAddress, re.Map["src-address"], re.Map["dst-address"],
		re.Map["ph2-state"], re.Map["invalid"], re.Map["comment"],
	)
}

func (c *ipsecCollector) collectPeerStats(re *proto.Sentence, ctx *context.Context) {
	for p := range peerMetricDescriptions {
		c.collectPeerMetricForProperty(p, re, ctx)
	}
}

func (c *ipsecCollector) collectPeerMetricForProperty(property string, re *proto.Sentence, ctx *context.Context) {
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
		v, err = strconv.ParseFloat(value, 64)
	}

	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse ipsec peers metric value")
		return
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(peerMetricDescriptions[property], prometheus.CounterValue, v,
		ctx.DeviceName, ctx.DeviceAddress,
		re.Map["local-address"], re.Map["remote-address"], re.Map["state"], re.Map["side"])
}
