package ospf_neighbors

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
	properties        = []string{"instance", "router-id", "address", "state", "state-changes"}
	metricDescription = metrics.BuildMetricDescription(prefix, "state_changes", "number of ospf neighbor state changes",
		[]string{"name", "address", "instance", "router_id", "neighbor_address", "state"},
	)
)

const prefix = "ospf_neighbor"

type ospfNeighborsCollector struct{}

func NewCollector() *ospfNeighborsCollector {
	return &ospfNeighborsCollector{}
}

func (c *ospfNeighborsCollector) Name() string {
	return prefix
}

func (c *ospfNeighborsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricDescription
}

func (c *ospfNeighborsCollector) Collect(ctx *context.Context) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch ospf neighbors: %w", err)
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *ospfNeighborsCollector) fetch(ctx *context.Context) ([]*proto.Sentence, error) {
	reply, err := ctx.RouterOSClient.Run(
		"/routing/ospf/neighbor/print",
		"=.proplist="+strings.Join(properties, ","),
	)
	if err != nil {
		return nil, err
	}

	return reply.Re, nil
}

func (c *ospfNeighborsCollector) collectForStat(re *proto.Sentence, ctx *context.Context) {
	value := re.Map["state-changes"]
	if len(value) == 0 {
		return
	}

	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		log.WithFields(log.Fields{
			"collector": c.Name(),
			"device":    ctx.DeviceName,
			"router_id": re.Map["router-id"],
			"value":     value,
			"error":     err,
		}).Error("failed to parse ospf neighbor metric value")
		return
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(metricDescription, prometheus.CounterValue, v,
		ctx.DeviceName, ctx.DeviceAddress,
		re.Map["instance"], re.Map["router-id"], re.Map["address"], re.Map["state"],
	)
}
