package _interface

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

func Test_interfaceCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("interface", c.Name())
}

func Test_interfaceCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "actual_mtu", "actual mtu of interface", labelNames),
		metrics.BuildMetricDescription(prefix, "rx_byte", "number of rx bytes on interface", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_byte", "number of tx bytes on interface", labelNames),
		metrics.BuildMetricDescription(prefix, "rx_packet", "number of rx packets on interface", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_packet", "number of tx packets on interface", labelNames),
		metrics.BuildMetricDescription(prefix, "rx_error", "number of rx errors on interface", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_error", "number of tx errors on interface", labelNames),
		metrics.BuildMetricDescription(prefix, "rx_drop", "number of dropped rx packets on interface", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_drop", "number of dropped tx packets on interface", labelNames),
		metrics.BuildMetricDescription(prefix, "link_downs", "number of times link has gone down on interface", labelNames),
	}, got)
}

func Test_interfaceCollector_Collect(t *testing.T) {
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
					"/interface/print",
					"=.proplist=name,type,disabled,comment,running,slave,actual-mtu,rx-byte,tx-byte,rx-packet,tx-packet,rx-error,tx-error,rx-drop,tx-drop,link-downs",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":       "ether1",
								"type":       "ethernet",
								"disabled":   "false",
								"comment":    "ether1",
								"running":    "true",
								"slave":      "false",
								"actual-mtu": "1500",
								"rx-byte":    "100",
								"tx-byte":    "10",
								"rx-packet":  "10",
								"tx-packet":  "1",
								"rx-error":   "0",
								"tx-error":   "0",
								"rx-drop":    "0",
								"tx-drop":    "0",
								"link-downs": "2",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "actual_mtu", "actual mtu of interface", labelNames),
					prometheus.GaugeValue, 1500, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_byte", "number of rx bytes on interface", labelNames),
					prometheus.CounterValue, 100, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_byte", "number of tx bytes on interface", labelNames),
					prometheus.CounterValue, 10, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_packet", "number of rx packets on interface", labelNames),
					prometheus.CounterValue, 10, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_packet", "number of tx packets on interface", labelNames),
					prometheus.CounterValue, 1, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_error", "number of rx errors on interface", labelNames),
					prometheus.CounterValue, 0, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_error", "number of tx errors on interface", labelNames),
					prometheus.CounterValue, 0, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_drop", "number of dropped rx packets on interface", labelNames),
					prometheus.CounterValue, 0, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_drop", "number of dropped tx packets on interface", labelNames),
					prometheus.CounterValue, 0, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "link_downs", "number of times link has gone down on interface", labelNames),
					prometheus.CounterValue, 2, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/interface/print",
						"=.proplist=name,type,disabled,comment,running,slave,actual-mtu,rx-byte,tx-byte,rx-packet,tx-packet,rx-error,tx-error,rx-drop,tx-drop,link-downs",
					}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch interface metrics: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/interface/print",
					"=.proplist=name,type,disabled,comment,running,slave,actual-mtu,rx-byte,tx-byte,rx-packet,tx-packet,rx-error,tx-error,rx-drop,tx-drop,link-downs",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":       "ether1",
								"type":       "ethernet",
								"disabled":   "false",
								"comment":    "ether1",
								"running":    "true",
								"slave":      "false",
								"actual-mtu": "1500",
								"rx-byte":    "a100",
								"tx-byte":    "b10",
								"rx-pckaet":  "c10",
								"tx-packet":  "d1",
								"rx-error":   "e0",
								"tx-error":   "f0",
								"rx-drop":    "g0",
								"tx-drop":    "h0",
								"link-downs": "i2",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "actual_mtu", "actual mtu of interface", labelNames),
					prometheus.GaugeValue, 1500, "device", "address", "ether1", "ethernet", "false", "ether1", "true", "false",
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
