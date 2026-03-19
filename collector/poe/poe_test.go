package poe

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

func Test_poeCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("poe", c.Name())
}

func Test_poeCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "current", "poe current in milliamps", labelNames),
		metrics.BuildMetricDescription(prefix, "voltage", "poe voltage in volts", labelNames),
		metrics.BuildMetricDescription(prefix, "power", "poe power in watts", labelNames),
	}, got)
}

func Test_poeCollector_Collect(t *testing.T) {
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
					"/interface/ethernet/poe/print",
					"=.proplist=name",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name": "poe1",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/interface/ethernet/poe/monitor",
					"=numbers=poe1",
					"=once=",
					"=.proplist=name,poe-out-current,poe-out-voltage,poe-out-power",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":            "poe1",
								"poe-out-current": "2",
								"poe-out-voltage": "12",
								"poe-out-power":   "24",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "current", "poe current in milliamps", labelNames),
					prometheus.GaugeValue, 2, "device", "address", "poe1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "voltage", "poe voltage in volts", labelNames),
					prometheus.GaugeValue, 12, "device", "address", "poe1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "power", "poe power in watts", labelNames),
					prometheus.GaugeValue, 24, "device", "address", "poe1",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/interface/ethernet/poe/print",
					"=.proplist=name",
				}...).Then(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch poe interface names: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/interface/ethernet/poe/print",
					"=.proplist=name",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name": "poe1",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/interface/ethernet/poe/monitor",
					"=numbers=poe1",
					"=once=",
					"=.proplist=name,poe-out-current,poe-out-voltage,poe-out-power",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":            "poe1",
								"poe-out-current": "2",
								"poe-out-voltage": "a12",
								"poe-out-power":   "b24",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "current", "poe current in milliamps", labelNames),
					prometheus.GaugeValue, 2, "device", "address", "poe1",
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
