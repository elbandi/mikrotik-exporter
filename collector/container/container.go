package container

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
)

var (
	statusProperties            = []string{"downloading/extracting", "\"download/extract failed\"", "starting", "starting-with-healthcheck", "running", "healthy", "unhealthy", "stopping", "stopped", "deleting"}
	containerProperties         = []string{"name", "cpu-usage", "memory-current"}
	layerProperties             = []string{"containers", "size"}
	labelNames                  = []string{"name", "address", "container_name"}
	containerMetricDescriptions = map[string]*metrics.MetricDescription{
		"status": {
			Desc:      metrics.BuildMetricDescription(prefix, "status", "container status", labelNames),
			ValueType: prometheus.CounterValue,
		},
		"cpu-usage": {
			Desc:      metrics.BuildMetricDescription(prefix, "cpu_usage", "CPU usage percentage", labelNames),
			ValueType: prometheus.GaugeValue,
		},
		"memory-current": {
			Desc:      metrics.BuildMetricDescription(prefix, "memory_current", "current memory usage", labelNames),
			ValueType: prometheus.GaugeValue,
		},
	}
	layersMetricDescription = metrics.BuildMetricDescription(prefix, "layer_size", "container layer size", labelNames)
)

const prefix = "container"

type containerCollector struct{}

func NewCollector() *containerCollector {
	return &containerCollector{}
}

func (c *containerCollector) Name() string {
	return prefix
}

func (c *containerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- layersMetricDescription
	for _, d := range containerMetricDescriptions {
		ch <- d.Desc
	}
}

func (c *containerCollector) Collect(ctx *context.Context) error {
	eg := errgroup.Group{}
	eg.Go(func() error {
		stats, err := c.fetchContainers(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch container metrics: %w", err)
		}

		for _, re := range stats {
			c.collectForStat(re, ctx)
		}

		return nil
	})
	eg.Go(func() error {
		stats, err := c.fetchContainerLayers(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch container layer metrics: %w", err)
		}

		for _, re := range stats {
			c.collectLayerStats(re, ctx)
		}

		return nil
	})
	return eg.Wait()
}

func (c *containerCollector) fetchContainers(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/container/print",
		"=.proplist="+strings.Join(append(append([]string{}, containerProperties...), statusProperties...), ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *containerCollector) fetchContainerLayers(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/container/layers/print",
		"=.proplist="+strings.Join(layerProperties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *containerCollector) collectLayerStats(re *proto.Sentence, ctx *context.Context) {
	value := re.Map["size"]
	if len(value) == 0 {
		return
	}
	name := re.Map["containers"]

	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"name":      name,
			"property":  "size",
			"value":     value,
			"error":     err,
		}).Error("failed to parse container layer metric value")
		return
	}
	ctx.MetricsChan <- prometheus.MustNewConstMetric(layersMetricDescription, prometheus.GaugeValue, v,
		ctx.DeviceName, ctx.DeviceAddress, name,
	)
}

func (c *containerCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	for p := range containerMetricDescriptions {
		switch p {
		case "status":
			c.collectMetricForHealthy(p, re, ctx)
		default:
			c.collectMetricForProperty(p, re, ctx)
		}
	}
}

func (c *containerCollector) getStatusValue(re *proto.Sentence) (int, error) {
	for i, s := range statusProperties {
		if "true" == re.Map[s] {
			return i, nil
		}
	}
	return -1, fmt.Errorf("status not found")
}

func (c *containerCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *context.Context) {
	value := re.Map[property]
	if len(value) == 0 {
		return
	}
	name := re.Map["name"]

	var (
		v   float64
		err error
	)
	switch property {
	default:
		v, err = strconv.ParseFloat(value, 64)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"name":      name,
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse container metric value")
		return
	}

	desc := containerMetricDescriptions[property]
	ctx.MetricsChan <- prometheus.MustNewConstMetric(desc.Desc, desc.ValueType, v, ctx.DeviceName, ctx.DeviceAddress, name)
}

func (c *containerCollector) collectMetricForHealthy(property string, re *proto.Sentence, ctx *context.Context) {
	value, err := c.getStatusValue(re)
	name := re.Map["name"]

	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"name":      name,
			"property":  property,
			"value":     value,
			"error":     err,
		}).Error("failed to parse container status value")
		return
	}
	if value < 0 {
		return
	}

	desc := containerMetricDescriptions[property]
	ctx.MetricsChan <- prometheus.MustNewConstMetric(desc.Desc, desc.ValueType, float64(value), ctx.DeviceName, ctx.DeviceAddress, name)
}
