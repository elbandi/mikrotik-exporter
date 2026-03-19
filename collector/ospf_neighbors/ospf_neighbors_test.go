package ospf_neighbors

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

func Test_ospfNeighborsCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("ospf_neighbor", c.Name())
}

func Test_ospfNeighborsCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "state_changes", "number of ospf neighbor state changes",
			[]string{"name", "address", "instance", "router_id", "neighbor_address", "state"},
		),
	}, got)
}

func Test_ospfNeighborsCollector_Collect(t *testing.T) {
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
					"/routing/ospf/neighbor/print",
					"=.proplist=instance,router-id,address,state,state-changes",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"instance":      "default",
								"router-id":     "192.168.1.1",
								"address":       "192.168.1.2",
								"state":         "Full",
								"state-changes": "3",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "state_changes", "number of ospf neighbor state changes",
						[]string{"name", "address", "instance", "router_id", "neighbor_address", "state"},
					),
					prometheus.CounterValue, 3, "device", "address", "default", "192.168.1.1", "192.168.1.2", "Full",
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/routing/ospf/neighbor/print",
					"=.proplist=instance,router-id,address,state,state-changes",
				}...).Then(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch ospf neighbors: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/routing/ospf/neighbor/print",
					"=.proplist=instance,router-id,address,state,state-changes",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"instance":      "default",
								"router-id":     "192.168.1.1",
								"address":       "192.168.1.2",
								"state":         "Full",
								"state-changes": "a3",
							},
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
