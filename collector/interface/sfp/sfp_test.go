package sfp

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

func Test_sfpCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("sfp", c.Name())
}

func Test_sfpCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "rx_status", "sfp rx status (no loss = 1)", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_status", "sfp tx status (no faults = 1)", labelNames),
		metrics.BuildMetricDescription(prefix, "temperature", "sfp temperature in degrees celsius", labelNames),
		metrics.BuildMetricDescription(prefix, "voltage", "sfp voltage in volts", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_bias", "sfp bias in milliamps", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_power", "sfp tx power in dbm", labelNames),
		metrics.BuildMetricDescription(prefix, "rx_power", "sfp rx power in dbm", labelNames),
	}, got)
}

func Test_sfpCollector_Collect(t *testing.T) {
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
								"name": "sfp1",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/interface/ethernet/monitor",
					"=numbers=sfp1",
					"=once=",
					"=.proplist=name,sfp-rx-loss,sfp-tx-fault,sfp-temperature,sfp-supply-voltage,sfp-tx-bias-current,sfp-tx-power,sfp-rx-power",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":                "sfp1",
								"sfp-rx-loss":         "false",
								"sfp-tx-fault":        "false",
								"sfp-temperature":     "30",
								"sfp-supply-voltage":  "12",
								"sfp-tx-bias-current": "1",
								"sfp-tx-power":        "2",
								"sfp-rx-power":        "3",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_status", "sfp rx status (no loss = 1)", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "sfp1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_status", "sfp tx status (no faults = 1)", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "sfp1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "temperature", "sfp temperature in degrees celsius", labelNames),
					prometheus.GaugeValue, 30, "device", "address", "sfp1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "voltage", "sfp voltage in volts", labelNames),
					prometheus.GaugeValue, 12, "device", "address", "sfp1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_bias", "sfp bias in milliamps", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "sfp1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_power", "sfp tx power in dbm", labelNames),
					prometheus.GaugeValue, 2, "device", "address", "sfp1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_power", "sfp rx power in dbm", labelNames),
					prometheus.GaugeValue, 3, "device", "address", "sfp1",
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
			errWant: "failed to fetch sfp interface names: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/interface/ethernet/print",
					"=.proplist=name",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name": "sfp1",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/interface/ethernet/monitor",
					"=numbers=sfp1",
					"=once=",
					"=.proplist=name,sfp-rx-loss,sfp-tx-fault,sfp-temperature,sfp-supply-voltage,sfp-tx-bias-current,sfp-tx-power,sfp-rx-power",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":                "sfp1",
								"sfp-rx-loss":         "false",
								"sfp-tx-fault":        "false",
								"sfp-temperature":     "a30",
								"sfp-supply-voltage":  "b12",
								"sfp-tx-bias-current": "c1",
								"sfp-tx-power":        "d2",
								"sfp-rx-power":        "e3",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_status", "sfp rx status (no loss = 1)", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "sfp1",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_status", "sfp tx status (no faults = 1)", labelNames),
					prometheus.GaugeValue, 1, "device", "address", "sfp1",
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
