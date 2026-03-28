package routes

import (
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
)

var (
	protocols                       = []string{"bgp", "static", "ospf", "dynamic", "connect", "rip"}
	labelNames                      = []string{"name", "address", "ip_version"}
	totalRoutesMetricDescription    = metrics.BuildMetricDescription(prefix, "total", "number of routes in rib", labelNames)
	protocolRoutesMetricDescription = metrics.BuildMetricDescription(prefix, "by_protocol", "number of routes per protocol in rib", append(labelNames, "protocol"))
)

const prefix = "routes"

type routesCollector struct {
	ipv6 bool
}

func NewCollector(ipv6 bool) *routesCollector {
	return &routesCollector{ipv6: ipv6}
}

func (c *routesCollector) Name() string {
	return prefix
}

func (c *routesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- totalRoutesMetricDescription
	ch <- protocolRoutesMetricDescription
}

func (c *routesCollector) Collect(ctx *context.Context) error {
	eg := errgroup.Group{}
	eg.Go(func() error {
		return c.collectForIPVersion("ip", "4", ctx)
	})

	if c.ipv6 {
		eg.Go(func() error {
			return c.collectForIPVersion("ipv6", "6", ctx)
		})
	}

	return eg.Wait()
}

func (c *routesCollector) collectForIPVersion(topic, ipVersion string, ctx *context.Context) error {
	eg := errgroup.Group{}
	eg.Go(func() error {
		return c.collectTotalCount(topic, ipVersion, ctx)
	})

	for i := range protocols {
		p := protocols[i]
		eg.Go(func() error {
			return c.collectCountByProtocol(topic, ipVersion, p, ctx)
		})
	}

	return eg.Wait()
}

func (c *routesCollector) collectTotalCount(topic, ipVersion string, ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		fmt.Sprintf("/%s/route/print", topic),
		"?active=true",
		"=count-only=",
	)
	if err != nil {
		return fmt.Errorf("failed to fetch total routes count: %w", err)
	}

	value := reply.Done.Map["ret"]
	if len(value) == 0 {
		return nil
	}

	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		log.WithFields(log.Fields{
			"collector":  c.Name(),
			"ip_version": ipVersion,
			"device":     ctx.DeviceName,
			"error":      err,
		}).Error("failed to parse routes metric value")
		return nil
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(totalRoutesMetricDescription, prometheus.GaugeValue, v,
		ctx.DeviceName, ctx.DeviceAddress, ipVersion,
	)

	return nil
}

func (c *routesCollector) collectCountByProtocol(topic, ipVersion, protocol string, ctx *context.Context) error {
	reply, err := ctx.RouterOSClient.Run(
		fmt.Sprintf("/%s/route/print", topic),
		"?active=true",
		fmt.Sprintf("?%s=true", protocol),
		"=count-only=",
	)
	if err != nil {
		return fmt.Errorf("failed to fetch routes by protocol: %w", err)
	}

	value := reply.Done.Map["ret"]
	if len(value) == 0 {
		return nil
	}

	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		log.WithFields(log.Fields{
			"collector":  c.Name(),
			"ip_version": ipVersion,
			"protocol":   protocol,
			"device":     ctx.DeviceName,
			"error":      err,
		}).Error("failed to parse routes metric value")
		return nil
	}

	ctx.MetricsChan <- prometheus.MustNewConstMetric(protocolRoutesMetricDescription, prometheus.GaugeValue, v,
		ctx.DeviceName, ctx.DeviceAddress, ipVersion, protocol,
	)

	return nil
}
