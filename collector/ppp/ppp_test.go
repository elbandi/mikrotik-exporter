package ppp

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

func Test_pppCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("ppp", c.Name())
}

func Test_pppCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "uptime", "ppp client uptime in seconds",
			[]string{"name", "address", "peer_name", "peer_address", "caller_id", "service", "comment"},
		),
	}, got)
}

func Test_pppCollector_Collect(t *testing.T) {
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
					"/ppp/active/print",
					"=.proplist=name,address,caller-id,service,comment,uptime",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"host":      "192.168.1.1",
								"name":      "test",
								"address":   "192.168.1.2",
								"caller-id": "10.10.101.5",
								"service":   "ovpn",
								"comment":   "comment",
								"uptime":    "9m57s",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "uptime", "ppp client uptime in seconds",
						[]string{"name", "address", "peer_name", "peer_address", "caller_id", "service", "comment"},
					),
					prometheus.CounterValue, 597, "device", "address",
					"test", "192.168.1.2", "10.10.101.5", "ovpn", "comment",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/ppp/active/print",
					"=.proplist=name,address,caller-id,service,comment,uptime",
				}...).Then(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch ppp: some fetch error",
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
