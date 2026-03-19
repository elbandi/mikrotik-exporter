package conntrack

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

func Test_conntrackCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("conntrack", c.Name())
}

func Test_conntrackCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "entries", "number of tracked connections", labelNames),
		metrics.BuildMetricDescription(prefix, "max_entries", "conntrack table capacity", labelNames),
	}, got)
}

func Test_conntrackCollector_Collect(t *testing.T) {
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
						"/ip/firewall/connection/tracking/print",
						"=.proplist=total-entries,max-entries",
					}, sentence)
				}).Return(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"total-entries": "100",
								"max-entries":   "1000",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "entries", "number of tracked connections", labelNames),
					prometheus.GaugeValue, 100, "device", "address",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "max_entries", "conntrack table capacity", labelNames),
					prometheus.GaugeValue, 1000, "device", "address",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/ip/firewall/connection/tracking/print",
						"=.proplist=total-entries,max-entries",
					}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch conntrack table metrics: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/ip/firewall/connection/tracking/print",
						"=.proplist=total-entries,max-entries",
					}, sentence)
				}).Return(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"total-entries": "100",
								"max-entries":   "a1000",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "entries", "number of tracked connections", labelNames),
					prometheus.GaugeValue, 100, "device", "address",
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
