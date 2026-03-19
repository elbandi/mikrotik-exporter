package bgp

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

func Test_bgpCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("bgp_session", c.Name())
}

func Test_bgpCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "established", "bgp session established (up = 1)", labelNames),
		metrics.BuildMetricDescription(prefix, "remote_messages", "number of bgp messages received per session", labelNames),
		metrics.BuildMetricDescription(prefix, "local_messages", "number of bgp messages sent per session", labelNames),
		metrics.BuildMetricDescription(prefix, "remote_bytes", "number of bytes received per session", labelNames),
		metrics.BuildMetricDescription(prefix, "local_bytes", "number of bytes sent per session", labelNames),
	}, got)
}

func Test_bgpCollector_Collect(t *testing.T) {
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
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/routing/bgp/session/print",
						"=.proplist=name,remote.as,remote.address,established,remote.messages,local.messages,remote.bytes,local.bytes",
					}, sentence)
				}).Return(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":            "session",
								"remote.as":       "65000",
								"remote.address":  "1.1.1.1",
								"established":     "true",
								"remote.messages": "111",
								"local.messages":  "11",
								"remote.bytes":    "222",
								"local.bytes":     "21",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "established", "bgp session established (up = 1)", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "session", "65000", "1.1.1.1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "remote_messages", "number of bgp messages received per session", labelNames),
					prometheus.CounterValue, 111, "device", "address", "session", "65000", "1.1.1.1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "local_messages", "number of bgp messages sent per session", labelNames),
					prometheus.CounterValue, 11, "device", "address", "session", "65000", "1.1.1.1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "remote_bytes", "number of bytes received per session", labelNames),
					prometheus.CounterValue, 222, "device", "address", "session", "65000", "1.1.1.1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "local_bytes", "number of bytes sent per session", labelNames),
					prometheus.CounterValue, 21, "device", "address", "session", "65000", "1.1.1.1",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/routing/bgp/session/print",
						"=.proplist=name,remote.as,remote.address,established,remote.messages,local.messages,remote.bytes,local.bytes",
					}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch bgp metrics: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/routing/bgp/session/print",
						"=.proplist=name,remote.as,remote.address,established,remote.messages,local.messages,remote.bytes,local.bytes",
					}, sentence)
				}).Return(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":            "session",
								"remote.as":       "65000",
								"remote.address":  "1.1.1.1",
								"established":     "true",
								"remote.messages": "d111",
								"local.messages":  "11",
								"remote.bytes":    "222",
								"local.bytes":     "21",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "established", "bgp session established (up = 1)", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "session", "65000", "1.1.1.1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "local_messages", "number of bgp messages sent per session", labelNames),
					prometheus.CounterValue, 11, "device", "address", "session", "65000", "1.1.1.1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "remote_bytes", "number of bytes received per session", labelNames),
					prometheus.CounterValue, 222, "device", "address", "session", "65000", "1.1.1.1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "local_bytes", "number of bytes sent per session", labelNames),
					prometheus.CounterValue, 21, "device", "address", "session", "65000", "1.1.1.1",
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
