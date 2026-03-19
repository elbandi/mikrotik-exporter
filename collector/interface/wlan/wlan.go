package wlan

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
	properties         = []string{"channel", "registered-clients", "noise-floor", "overall-tx-ccq"}
	labelNames         = []string{"name", "address", "interface", "channel"}
	metricDescriptions = map[string]*prometheus.Desc{
		"registered-clients": metrics.BuildMetricDescription(prefix, "registered_clients", "number of registered clients on wlan interface", labelNames),
		"noise-floor":        metrics.BuildMetricDescription(prefix, "noise_floor", "noise floor for wlan interface in dbm", labelNames),
		"overall-tx-ccq":     metrics.BuildMetricDescription(prefix, "tx_ccq", "tx ccq on wlan interface in percent", labelNames),
	}
)

const prefix = "wlan_interface"

type wlanInterfaceCollector struct{}

func NewCollector() *wlanInterfaceCollector {
	return &wlanInterfaceCollector{}
}

func (c *wlanInterfaceCollector) Name() string {
	return prefix
}

func (c *wlanInterfaceCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d
	}
}

func (c *wlanInterfaceCollector) Collect(ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/wireless/print",
		"?disabled=false",
		"=.proplist=name",
	)
	if err != nil {
		return fmt.Errorf("failed to fetch wlan interface names: %w", err)
	}

	interfaces := make([]string, 0, len(reply.Re))
	for _, re := range reply.Re {
		interfaces = append(interfaces, re.Map["name"])
	}

	return c.collectForInterfaces(interfaces, ctx)
}

func (c *wlanInterfaceCollector) collectForInterfaces(interfaces []string, ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/wireless/monitor",
		"=numbers="+strings.Join(interfaces, ","),
		"=once=",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return fmt.Errorf("failed to fetch wlan interface monitor info: %w", err)
	}

	for i, re := range reply.Re {
		c.collectMetricForInterface(interfaces[i], re, ctx)
	}

	return nil
}

func (c *wlanInterfaceCollector) collectMetricForInterface(iface string, re *proto.Sentence, ctx *context.Context) {
	for property := range metricDescriptions {
		value := re.Map[property]
		if len(value) == 0 {
			continue
		}

		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			log.WithFields(log.Fields{
				"collector": c.Name(),
				"property":  property,
				"interface": iface,
				"device":    ctx.DeviceName,
				"error":     err,
			}).Error("failed to parse wlan interface metric value")
			continue
		}

		ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions[property], prometheus.GaugeValue, v,
			ctx.DeviceName, ctx.DeviceAddress, iface, re.Map["channel"],
		)
	}
}
