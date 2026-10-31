package container

import (
	"errors"
	"testing"

	"github.com/go-routeros/routeros/v3"
	"github.com/go-routeros/routeros/v3/proto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
	"github.com/ogi4i/mikrotik-exporter/routeros/mocks"
)

func Test_containerCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("container", c.Name())
}

func Test_containerCollector_Describe(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	ch := make(chan *prometheus.Desc)
	done := make(chan struct{})
	var got []*prometheus.Desc
	go func() {
		defer close(done)
		for desc := range ch {
			got = append(got, desc)
		}
	}()

	c.Describe(ch)
	close(ch)

	<-done
	r.ElementsMatch([]*prometheus.Desc{
		metrics.BuildMetricDescription(prefix, "status", "container status", labelNames),
		metrics.BuildMetricDescription(prefix, "cpu_usage", "CPU usage percentage", labelNames),
		metrics.BuildMetricDescription(prefix, "memory_current", "current memory usage", labelNames),
		metrics.BuildMetricDescription(prefix, "layer_size", "container layer size", labelNames),
	}, got)
}

func Test_containerCollector_Collect(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	routerOSClientMock := mocks.NewClientMock(t)
	resetMocks := func() {
		routerOSClientMock = mocks.NewClientMock(t)
	}

	testCases := []struct {
		name     string
		setMocks func()
		want     []prometheus.Metric
		errWant  string
	}{
		{
			name: "success",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/container/print",
					"=.proplist=name,cpu-usage,memory-current,downloading/extracting,\"download/extract failed\",starting,starting-with-healthcheck,running,healthy,unhealthy,stopping,stopped,deleting",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":           "pihole",
								"cpu-usage":      "0",
								"memory-current": "123456",
								"running":        "true",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/container/layers/print",
					"=.proplist=containers,size",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"containers": "pihole",
								"size":       "654321",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "status", "container status", labelNames),
					prometheus.CounterValue, 4, "device", "address", "pihole",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "cpu_usage", "CPU usage percentage", labelNames),
					prometheus.GaugeValue, 0, "device", "address", "pihole",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "memory_current", "current memory usage", labelNames),
					prometheus.GaugeValue, 123456, "device", "address", "pihole",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "layer_size", "container layer size", labelNames),
					prometheus.GaugeValue, 654321, "device", "address", "pihole",
				),
			},
		},
		{
			name: "container fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/container/print",
					"=.proplist=name,cpu-usage,memory-current,downloading/extracting,\"download/extract failed\",starting,starting-with-healthcheck,running,healthy,unhealthy,stopping,stopped,deleting",
				}...).Then(nil, errors.New("some fetch error"))

				routerOSClientMock.RunMock.When([]string{
					"/container/layers/print",
					"=.proplist=containers,size",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{},
				}, nil)
			},
			errWant: "failed to fetch container metrics: some fetch error",
		},
		{
			name: "container layers fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/container/print",
					"=.proplist=name,cpu-usage,memory-current,downloading/extracting,\"download/extract failed\",starting,starting-with-healthcheck,running,healthy,unhealthy,stopping,stopped,deleting",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/container/layers/print",
					"=.proplist=containers,size",
				}...).Then(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch container layer metrics: some fetch error",
		},
		{
			name: "invalid container status",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/container/print",
					"=.proplist=name,cpu-usage,memory-current,downloading/extracting,\"download/extract failed\",starting,starting-with-healthcheck,running,healthy,unhealthy,stopping,stopped,deleting",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":           "pihole",
								"cpu-usage":      "0",
								"memory-current": "123456",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/container/layers/print",
					"=.proplist=containers,size",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"containers": "pihole",
								"size":       "654321",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "cpu_usage", "CPU usage percentage", labelNames),
					prometheus.GaugeValue, 0, "device", "address", "pihole",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "memory_current", "current memory usage", labelNames),
					prometheus.GaugeValue, 123456, "device", "address", "pihole",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "layer_size", "container layer size", labelNames),
					prometheus.GaugeValue, 654321, "device", "address", "pihole",
				),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetMocks()
			tc.setMocks()
			defer routerOSClientMock.MinimockFinish()

			ch := make(chan prometheus.Metric)
			done := make(chan struct{})
			var got []prometheus.Metric
			go func() {
				defer close(done)
				for desc := range ch {
					got = append(got, desc)
				}
			}()

			errGot := c.Collect(&context.Context{
				RouterOSClient: routerOSClientMock,
				MetricsChan:    ch,
				DeviceName:     "device",
				DeviceAddress:  "address",
			})
			close(ch)
			if len(tc.errWant) != 0 {
				r.EqualError(errGot, tc.errWant)
			} else {
				r.NoError(errGot)
			}

			<-done
			r.ElementsMatch(tc.want, got)
		})
	}
}
