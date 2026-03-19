package ethernet

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

func Test_ethernetCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("ethernet", c.Name())
}

func Test_ethernetCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "status", "ethernet interface status (up = 1)", labelNames),
		metrics.BuildMetricDescription(prefix, "rate", "ethernet interface link rate in mbps", labelNames),
		metrics.BuildMetricDescription(prefix, "full_duplex", "ethernet interface full duplex status (full duplex = 1)", labelNames),
	}, got)
}

func Test_ethernetCollector_Collect(t *testing.T) {
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
					"/interface/ethernet/print",
					"=.proplist=name",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name": "ether1",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/interface/ethernet/monitor",
					"=numbers=ether1",
					"=once=",
					"=.proplist=name,status,rate,full-duplex,comment",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":        "ether1",
								"status":      "link-ok",
								"rate":        "1Gbps",
								"full-duplex": "true",
								"comment":     "Test",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "status", "ethernet interface status (up = 1)", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "ether1", "Test",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rate", "ethernet interface link rate in mbps", labelNames),
					prometheus.GaugeValue, 1000, "device", "address", "ether1", "Test",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "full_duplex", "ethernet interface full duplex status (full duplex = 1)", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "ether1", "Test",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/interface/ethernet/print",
						"=.proplist=name",
					}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch ethernet interface names: some fetch error",
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
