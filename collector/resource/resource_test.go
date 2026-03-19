package resource

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

func Test_resourceCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("system", c.Name())
}

func Test_resourceCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "free_memory", "amount of free memory in bytes", labelNames),
		metrics.BuildMetricDescription(prefix, "total_memory", "amount of total memory in bytes", labelNames),
		metrics.BuildMetricDescription(prefix, "cpu_load", "cpu load in percent", labelNames),
		metrics.BuildMetricDescription(prefix, "free_hdd_space", "amount of free hdd space in bytes", labelNames),
		metrics.BuildMetricDescription(prefix, "total_hdd_space", "amount of total hdd space in bytes", labelNames),
		metrics.BuildMetricDescription(prefix, "uptime", "system uptime in seconds", labelNames),
	}, got)
}

func Test_resourceCollector_Collect(t *testing.T) {
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
					"/system/resource/print",
					"=.proplist=free-memory,total-memory,cpu-load,free-hdd-space,total-hdd-space,uptime,board-name,version",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"free-memory":     "1.0",
								"total-memory":    "2.0",
								"cpu-load":        "0.1",
								"free-hdd-space":  "10.0",
								"total-hdd-space": "20.0",
								"uptime":          "1d1h1m1s",
								"board-name":      "boardname",
								"version":         "version",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "free_memory", "amount of free memory in bytes", labelNames),
					prometheus.GaugeValue, 1.0, "device", "address", "boardname", "version",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "total_memory", "amount of total memory in bytes", labelNames),
					prometheus.GaugeValue, 2.0, "device", "address", "boardname", "version",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "cpu_load", "cpu load in percent", labelNames),
					prometheus.GaugeValue, 0.1, "device", "address", "boardname", "version",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "free_hdd_space", "amount of free hdd space in bytes", labelNames),
					prometheus.GaugeValue, 10.0, "device", "address", "boardname", "version",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "total_hdd_space", "amount of total hdd space in bytes", labelNames),
					prometheus.GaugeValue, 20.0, "device", "address", "boardname", "version",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "uptime", "system uptime in seconds", labelNames),
					prometheus.CounterValue, 90061, "device", "address", "boardname", "version",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/system/resource/print",
					"=.proplist=free-memory,total-memory,cpu-load,free-hdd-space,total-hdd-space,uptime,board-name,version",
				}...).Then(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch resource metrics: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/system/resource/print",
					"=.proplist=free-memory,total-memory,cpu-load,free-hdd-space,total-hdd-space,uptime,board-name,version",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"free-memory":     "1,0",
								"total-memory":    "2,0",
								"cpu-load":        "0,1",
								"free-hdd-space":  "10,0",
								"total-hdd-space": "20,0",
								"uptime":          "1d1h1m1s",
								"board-name":      "boardname",
								"version":         "version",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "uptime", "system uptime in seconds", labelNames),
					prometheus.CounterValue, 90061, "device", "address", "boardname", "version",
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
