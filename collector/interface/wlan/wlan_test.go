package wlan

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

func Test_wlanInterfaceCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("wlan_interface", c.Name())
}

func Test_wlanInterfaceCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "registered_clients", "number of registered clients on wlan interface", labelNames),
		metrics.BuildMetricDescription(prefix, "noise_floor", "noise floor for wlan interface in dbm", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_ccq", "tx ccq on wlan interface in percent", labelNames),
	}, got)
}

func Test_wlanInterfaceCollector_Collect(t *testing.T) {
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
					"/interface/wireless/print",
					"?disabled=false",
					"=.proplist=name",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name": "wlan1",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/interface/wireless/monitor",
					"=numbers=wlan1",
					"=once=",
					"=.proplist=channel,registered-clients,noise-floor,overall-tx-ccq",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"channel":            "channel",
								"registered-clients": "3",
								"noise-floor":        "-100",
								"overall-tx-ccq":     "98",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "registered_clients", "number of registered clients on wlan interface", labelNames),
					prometheus.GaugeValue, 3, "device", "address", "wlan1", "channel",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "noise_floor", "noise floor for wlan interface in dbm", labelNames),
					prometheus.GaugeValue, -100, "device", "address", "wlan1", "channel",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_ccq", "tx ccq on wlan interface in percent", labelNames),
					prometheus.GaugeValue, 98, "device", "address", "wlan1", "channel",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/interface/wireless/print",
						"?disabled=false",
						"=.proplist=name",
					}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch wlan interface names: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/interface/wireless/print",
					"?disabled=false",
					"=.proplist=name",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name": "wlan1",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/interface/wireless/monitor",
					"=numbers=wlan1",
					"=once=",
					"=.proplist=channel,registered-clients,noise-floor,overall-tx-ccq",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"channel":            "channel",
								"registered-clients": "3",
								"noise-floor":        "a-100",
								"overall-tx-ccq":     "b98",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "registered_clients", "number of registered clients on wlan interface", labelNames),
					prometheus.GaugeValue, 3, "device", "address", "wlan1", "channel",
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
