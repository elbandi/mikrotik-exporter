package kid_control

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

func Test_kidControlCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("kid_control", c.Name())
}

func Test_kidControlCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "device_since_idle", "time in seconds since last activity", labelNames),
		metrics.BuildMetricDescription(prefix, "device_rx_bytes", "received bytes from device", labelNames),
		metrics.BuildMetricDescription(prefix, "device_tx_bytes", "sent bytes to device", labelNames),
	}, got)
}

func Test_kidControlCollector_Collect(t *testing.T) {
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
						"/ip/kid-control/device/print",
						"=.proplist=ip-address,mac-address,bytes-down,bytes-up,idle-time",
					}, sentence)
				}).Return(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"ip-address":  "192.168.1.1",
								"mac-address": "00:11:22:33:44:55",
								"bytes-down":  "100",
								"bytes-up":    "10",
								"idle-time":   "10s",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "device_since_idle", "time in seconds since last activity",
						[]string{"name", "address", "ip_address", "mac_address"},
					),
					prometheus.GaugeValue, 10.0, "device", "address", "192.168.1.1", "00:11:22:33:44:55",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "device_rx_bytes", "received bytes from device",
						[]string{"name", "address", "ip_address", "mac_address"},
					),
					prometheus.CounterValue, 100.0, "device", "address", "192.168.1.1", "00:11:22:33:44:55",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "device_tx_bytes", "sent bytes to device",
						[]string{"name", "address", "ip_address", "mac_address"},
					),
					prometheus.CounterValue, 10.0, "device", "address", "192.168.1.1", "00:11:22:33:44:55",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/ip/kid-control/device/print",
						"=.proplist=ip-address,mac-address,bytes-down,bytes-up,idle-time",
					}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch kid control: some fetch error",
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
