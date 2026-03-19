package lte

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

func Test_lteCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("lte", c.Name())
}

func Test_lteCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "rssi", "lte interface received signal strength indicator", labelNames),
		metrics.BuildMetricDescription(prefix, "rsrp", "lte interface reference signal received power", labelNames),
		metrics.BuildMetricDescription(prefix, "rsrq", "lte interface reference signal received quality", labelNames),
		metrics.BuildMetricDescription(prefix, "sinr", "lte interface signal interference to noise ratio", labelNames),
	}, got)
}

func Test_lteCollector_Collect(t *testing.T) {
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
					"/interface/lte/print",
					"?disabled=false",
					"=.proplist=name",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name": "lte1",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/interface/lte/info",
					"=numbers=lte1",
					"=once=",
					"=.proplist=current-cellid,primary-band,ca-band,rssi,rsrp,rsrq,sinr",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"current-cellid": "current-cellid",
								"primary-band":   "primary-band",
								"ca-band":        "ca-band",
								"rssi":           "1",
								"rsrp":           "2",
								"rsrq":           "3",
								"sinr":           "4",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rssi", "lte interface received signal strength indicator", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "lte1", "current-cellid", "primary-band", "ca-band",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rsrp", "lte interface reference signal received power", labelNames),
					prometheus.GaugeValue, 2, "device", "address", "lte1", "current-cellid", "primary-band", "ca-band",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rsrq", "lte interface reference signal received quality", labelNames),
					prometheus.GaugeValue, 3, "device", "address", "lte1", "current-cellid", "primary-band", "ca-band",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "sinr", "lte interface signal interference to noise ratio", labelNames),
					prometheus.GaugeValue, 4, "device", "address", "lte1", "current-cellid", "primary-band", "ca-band",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/interface/lte/print",
						"?disabled=false",
						"=.proplist=name",
					}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch lte interface names: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/interface/lte/print",
					"?disabled=false",
					"=.proplist=name",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name": "lte1",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/interface/lte/info",
					"=numbers=lte1",
					"=once=",
					"=.proplist=current-cellid,primary-band,ca-band,rssi,rsrp,rsrq,sinr",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"current-cellid": "current-cellid",
								"primary-band":   "primary-band",
								"ca-band":        "ca-band",
								"rssi":           "1",
								"rsrp":           "a2",
								"rsrq":           "b3",
								"sinr":           "c4",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rssi", "lte interface received signal strength indicator", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "lte1", "current-cellid", "primary-band", "ca-band",
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
