package stations

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
	properties         = []string{"interface", "mac-address", "uptime", "signal-to-noise", "signal-strength-ch0", "signal-strength-ch1", "tx-ccq", "rx-rate", "tx-rate", "packets", "bytes", "frames"}
	labelNames         = []string{"name", "address", "interface", "mac_address"}
	metricDescriptions = map[string]metrics.MetricDescription{
		"uptime": {
			Desc:      metrics.BuildMetricDescription(prefix, "uptime", "wlan station uptime in seconds", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"signal-to-noise": {
			Desc:      metrics.BuildMetricDescription(prefix, "signal_to_noise_ratio", "wlan station signal to noise ratio", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"signal-strength-ch0": {
			Desc:      metrics.BuildMetricDescription(prefix, "signal_strength_ch0", "wlan station signal strength on ch0 in dbm", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"signal-strength-ch1": {
			Desc:      metrics.BuildMetricDescription(prefix, "signal_strength_ch1", "wlan station signal strength on ch1 in dbm", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"tx-ccq": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_ccq", "wlan station tx ccq in percent", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"rx-rate": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_rate", "wlan station rx rate in mbps", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"tx-rate": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_rate", "wlan station tx rate in mbps", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"tx_packets": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_packets", "number of tx packets per wlan station", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"rx_packets": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_packets", "number of rx packets per wlan station", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"tx_bytes": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_bytes", "number of tx bytes per wlan station", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"rx_bytes": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_bytes", "number of rx bytes per wlan station", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"tx_frames": {
			Desc:      metrics.BuildMetricDescription(prefix, "tx_frames", "number of tx frames per wlan station", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"rx_frames": {
			Desc:      metrics.BuildMetricDescription(prefix, "rx_frames", "number of rx frames per wlan station", labelNames),
			ValueType: prometheus.CounterValue,
		},
	}
)

const prefix = "wlan_station"

type wlanStationsCollector struct{}

func NewCollector() *wlanStationsCollector {
	return &wlanStationsCollector{}
}

func (c *wlanStationsCollector) Name() string {
	return prefix
}

func (c *wlanStationsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range metricDescriptions {
		ch <- d.Desc
	}
}

func (c *wlanStationsCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch wlan station info: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *wlanStationsCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/interface/wireless/registration-table/print",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *wlanStationsCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	for p := range metricDescriptions {
		switch p {
		case "tx_packets": // pass, only need to collect once
		case "rx_packets":
			c.collectMetricForTXRXCounters("packets", re, ctx)
		case "tx_bytes": // pass, only need to collect once
		case "rx_bytes":
			c.collectMetricForTXRXCounters("bytes", re, ctx)
		case "tx_frames": // pass, only need to collect once
		case "rx_frames":
			c.collectMetricForTXRXCounters("frames", re, ctx)
		default:
			c.collectMetricForProperty(p, re, ctx)
		}
	}
}

func (c *wlanStationsCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *context.Context) {
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
	case "rx-rate", "tx-rate":
		v, err = parsers.ParseWirelessRate(value)
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
		}).Error("failed to parse wlan station metric value")
		return
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions[property].Desc, metricDescriptions[property].ValueType, v,
		ctx.DeviceName, ctx.DeviceAddress, re.Map["interface"], re.Map["mac-address"],
	)
}

func (c *wlanStationsCollector) collectMetricForTXRXCounters(property string, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		return
	}

	tx, rx, err := parsers.ParseCommaSeparatedValuesToFloat64(value)
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse wlan station metric value")
		return
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions["tx_"+property].Desc, metricDescriptions["tx_"+property].ValueType,
		tx, ctx.DeviceName, ctx.DeviceAddress, re.Map["interface"], re.Map["mac-address"],
	)
	ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescriptions["rx_"+property].Desc, metricDescriptions["rx_"+property].ValueType,
		rx, ctx.DeviceName, ctx.DeviceAddress, re.Map["interface"], re.Map["mac-address"],
	)
}
