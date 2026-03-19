package dns

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

func Test_dnsCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("dns", c.Name())
}

func Test_dnsCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "cache", "dns cache items",
			[]string{"name", "address", "type"},
		),
	}, got)
}

func Test_dnsCollector_Collect(t *testing.T) {
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
				routerOSClientMock.RunMock.
					When([]string{
						"/ip/dns/cache/print",
						"?static=no",
						"=.proplist=type,name,static",
					}...).
					Then(&routeros.Reply{
						Re: []*proto.Sentence{
							{
								Map: map[string]string{
									"type": "A",
									"name": "dns1",
								},
							},
							{
								Map: map[string]string{
									"type": "A",
									"name": "dns2",
								},
							},
							{
								Map: map[string]string{
									"type": "CNAME",
									"name": "dns3",
								},
							},
						},
					}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "cache", "dns cache items",
						[]string{"name", "address", "type"},
					),
					prometheus.GaugeValue, 2, "device", "address", "A",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "cache", "dns cache items",
						[]string{"name", "address", "type"},
					),
					prometheus.GaugeValue, 1, "device", "address", "CNAME",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/ip/dns/cache/print",
					"?static=no",
					"=.proplist=type,name,static",
				}...).Then(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch dns cache: some fetch error",
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
