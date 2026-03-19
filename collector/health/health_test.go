package health

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

func Test_healthCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("health", c.Name())
}

func Test_healthCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "voltage", "input voltage to routeros board in volts", labelNames),
		metrics.BuildMetricDescription(prefix, "board_temperature", "temperature of routeros board in degrees celsius", labelNames),
		metrics.BuildMetricDescription(prefix, "cpu_temperature", "cpu temperature in degrees celsius", labelNames),
	}, got)
}

func Test_healthCollector_Collect(t *testing.T) {
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
				routerOSClientMock.RunMock.When([]string{"/system/health/print"}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"voltage":         "12",
								"temperature":     "30",
								"cpu-temperature": "40",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "voltage", "input voltage to routeros board in volts", labelNames),
					prometheus.GaugeValue, 12, "device", "address",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "board_temperature", "temperature of routeros board in degrees celsius", labelNames),
					prometheus.GaugeValue, 30, "device", "address",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "cpu_temperature", "cpu temperature in degrees celsius", labelNames),
					prometheus.GaugeValue, 40, "device", "address",
				),
			},
		},
		{
			name: "success_ros7",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{"/system/health/print"}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name":  "cpu-temperature",
								"value": "40",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "cpu_temperature", "cpu temperature in degrees celsius", labelNames),
					prometheus.GaugeValue, 40, "device", "address",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{"/system/health/print"}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch system health: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{"/system/health/print"}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"voltage":         "12",
								"temperature":     "30",
								"cpu-temperature": "a40",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "voltage", "input voltage to routeros board in volts", labelNames),
					prometheus.GaugeValue, 12, "device", "address",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "board_temperature", "temperature of routeros board in degrees celsius", labelNames),
					prometheus.GaugeValue, 30, "device", "address",
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
