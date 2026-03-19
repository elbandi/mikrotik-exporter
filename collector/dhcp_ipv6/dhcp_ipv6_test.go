package dhcp_ipv6

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

func Test_dhcpIPv6Collector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("dhcp_ipv6", c.Name())
}

func Test_dhcpIPv6Collector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "binding_count", "number of active bindings per dhcp ipv6 server",
			[]string{"name", "address", "server"},
		),
	}, got)
}

func Test_dhcpIPv6Collector_Collect(t *testing.T) {
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
					"/ipv6/dhcp-server/print",
					"=.proplist=name",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name": "name",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/ipv6/dhcp-server/binding/print",
					"?server=name",
					"=count-only=",
				}...).Then(&routeros.Reply{
					Done: &proto.Sentence{
						Map: map[string]string{
							"ret": "1",
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "binding_count", "number of active bindings per dhcp ipv6 server",
						[]string{"name", "address", "server"},
					),
					prometheus.GaugeValue, 1, "device", "address", "name",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/ipv6/dhcp-server/print",
						"=.proplist=name",
					}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch dhcp ipv6 server name: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/ipv6/dhcp-server/print",
					"=.proplist=name",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"name": "name",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/ipv6/dhcp-server/binding/print",
					"?server=name",
					"=count-only=",
				}...).Then(&routeros.Reply{
					Done: &proto.Sentence{
						Map: map[string]string{
							"ret": "a",
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{},
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
