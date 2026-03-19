package capsman

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

func Test_capsmanCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("capsman_client", c.Name())
}

func Test_capsmanCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "uptime", "capsman client uptime in seconds", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_signal", "capsman client tx signal strength in dbm", labelNames),
		metrics.BuildMetricDescription(prefix, "rx_signal", "capsman client rx signal strength in dbm", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_packets", "capsman client tx packets count", labelNames),
		metrics.BuildMetricDescription(prefix, "tx_bytes", "capsman client tx bytes count", labelNames),
		metrics.BuildMetricDescription(prefix, "rx_packets", "capsman client rx packets count", labelNames),
		metrics.BuildMetricDescription(prefix, "rx_bytes", "capsman client rx bytes count", labelNames),
	}, got)
}

func Test_capsmanCollector_Collect(t *testing.T) {
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
						"/caps-man/registration-table/print",
						"=.proplist=interface,mac-address,ssid,uptime,tx-signal,rx-signal,packets,bytes",
					}, sentence)
				}).Return(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"interface":   "wlan1",
								"mac-address": "mac-address",
								"ssid":        "ssid",
								"uptime":      "1m1s",
								"tx-signal":   "20",
								"rx-signal":   "30",
								"packets":     "100,10",
								"bytes":       "2000,200",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "uptime", "capsman client uptime in seconds", labelNames),
					prometheus.CounterValue, 61, "device", "address", "wlan1", "mac-address", "ssid",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_signal", "capsman client tx signal strength in dbm", labelNames),
					prometheus.GaugeValue, 20, "device", "address", "wlan1", "mac-address", "ssid",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_signal", "capsman client rx signal strength in dbm", labelNames),
					prometheus.GaugeValue, 30, "device", "address", "wlan1", "mac-address", "ssid",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_packets", "capsman client tx packets count", labelNames),
					prometheus.CounterValue, 100, "device", "address", "wlan1", "mac-address", "ssid",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_packets", "capsman client rx packets count", labelNames),
					prometheus.CounterValue, 10, "device", "address", "wlan1", "mac-address", "ssid",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_bytes", "capsman client tx bytes count", labelNames),
					prometheus.CounterValue, 2000, "device", "address", "wlan1", "mac-address", "ssid",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_bytes", "capsman client rx bytes count", labelNames),
					prometheus.CounterValue, 200, "device", "address", "wlan1", "mac-address", "ssid",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/caps-man/registration-table/print",
						"=.proplist=interface,mac-address,ssid,uptime,tx-signal,rx-signal,packets,bytes",
					}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch capsman station metrics: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/caps-man/registration-table/print",
						"=.proplist=interface,mac-address,ssid,uptime,tx-signal,rx-signal,packets,bytes",
					}, sentence)
				}).Return(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"interface":   "wlan1",
								"mac-address": "mac-address",
								"ssid":        "ssid",
								"uptime":      "1m1s",
								"tx-signal":   "20",
								"rx-signal":   "30",
								"packets":     "100,10",
								"bytes":       "2000200",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "uptime", "capsman client uptime in seconds", labelNames),
					prometheus.CounterValue, 61, "device", "address", "wlan1", "mac-address", "ssid",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_signal", "capsman client tx signal strength in dbm", labelNames),
					prometheus.GaugeValue, 20, "device", "address", "wlan1", "mac-address", "ssid",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_signal", "capsman client rx signal strength in dbm", labelNames),
					prometheus.GaugeValue, 30, "device", "address", "wlan1", "mac-address", "ssid",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tx_packets", "capsman client tx packets count", labelNames),
					prometheus.CounterValue, 100, "device", "address", "wlan1", "mac-address", "ssid",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "rx_packets", "capsman client rx packets count", labelNames),
					prometheus.CounterValue, 10, "device", "address", "wlan1", "mac-address", "ssid",
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
