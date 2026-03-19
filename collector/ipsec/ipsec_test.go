package ipsec

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"gopkg.in/routeros.v2"
	"gopkg.in/routeros.v2/proto"

	"github.com/ogi4i/mikrotik-exporter/collector/context"
	"github.com/ogi4i/mikrotik-exporter/metrics"
	"github.com/ogi4i/mikrotik-exporter/routeros/mocks"
)

func Test_ipsecCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("ipsec", c.Name())
}

func Test_ipsecCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "tunnel_active", "active ipsec tunnels (active = 1)",
			[]string{"name", "address", "src_address", "dst_address", "ph2_state", "invalid", "comment"},
		),
		metrics.BuildMetricDescription(prefix, "peer_uptime", "ipsec peer uptime in seconds", peerLabelNames),
		metrics.BuildMetricDescription(prefix, "peer_rx_bytes", "number of ipsec peer rx bytes", peerLabelNames),
		metrics.BuildMetricDescription(prefix, "peer_rx_packets", "number of ipsec peer rx packets", peerLabelNames),
		metrics.BuildMetricDescription(prefix, "peer_tx_bytes", "number of ipsec peer tx bytes", peerLabelNames),
		metrics.BuildMetricDescription(prefix, "peer_tx_packets", "number of ipsec peer tx packets", peerLabelNames),
	}, got)
}

func Test_ipsecCollector_Collect(t *testing.T) {
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
					"/ip/ipsec/policy/print",
					"?disabled=false",
					"?dynamic=false",
					"=.proplist=src-address,dst-address,ph2-state,invalid,active,comment",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"src-address": "192.168.1.1",
								"dst-address": "192.168.2.1",
								"ph2-state":   "established",
								"invalid":     "false",
								"active":      "true",
								"comment":     "comment",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/ip/ipsec/active-peers/print",
					"=.proplist=local-address,remote-address,state,side,uptime,rx-bytes,rx-packets,tx-bytes,tx-packets",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"local-address":  "192.168.1.1",
								"remote-address": "192.168.2.1",
								"state":          "established",
								"side":           "responder",
								"uptime":         "1m40s",
								"rx-bytes":       "100",
								"rx-packets":     "10",
								"tx-bytes":       "10",
								"tx-packets":     "1",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tunnel_active", "active ipsec tunnels (active = 1)",
						[]string{"name", "address", "src_address", "dst_address", "ph2_state", "invalid", "comment"},
					),
					prometheus.GaugeValue, 1, "device", "address", "192.168.1.1", "192.168.2.1", "established", "false", "comment",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "peer_uptime", "ipsec peer uptime in seconds", peerLabelNames),
					prometheus.CounterValue, 100, "device", "address", "192.168.1.1", "192.168.2.1", "established", "responder",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "peer_rx_bytes", "number of ipsec peer rx bytes", peerLabelNames),
					prometheus.CounterValue, 100, "device", "address", "192.168.1.1", "192.168.2.1", "established", "responder",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "peer_rx_packets", "number of ipsec peer rx packets", peerLabelNames),
					prometheus.CounterValue, 10, "device", "address", "192.168.1.1", "192.168.2.1", "established", "responder",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "peer_tx_bytes", "number of ipsec peer tx bytes", peerLabelNames),
					prometheus.CounterValue, 10, "device", "address", "192.168.1.1", "192.168.2.1", "established", "responder",
				),
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "peer_tx_packets", "number of ipsec peer tx packets", peerLabelNames),
					prometheus.CounterValue, 1, "device", "address", "192.168.1.1", "192.168.2.1", "established", "responder",
				),
			},
		},
		{
			name: "tunnel fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/ip/ipsec/policy/print",
					"?disabled=false",
					"?dynamic=false",
					"=.proplist=src-address,dst-address,ph2-state,invalid,active,comment",
				}...).Then(nil, errors.New("some fetch error"))

				routerOSClientMock.RunMock.When([]string{
					"/ip/ipsec/active-peers/print",
					"=.proplist=local-address,remote-address,state,side,uptime,rx-bytes,rx-packets,tx-bytes,tx-packets",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{},
				}, nil)
			},
			errWant: "failed to fetch ipsec tunnels: some fetch error",
		},
		{
			name: "peers fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/ip/ipsec/policy/print",
					"?disabled=false",
					"?dynamic=false",
					"=.proplist=src-address,dst-address,ph2-state,invalid,active,comment",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/ip/ipsec/active-peers/print",
					"=.proplist=local-address,remote-address,state,side,uptime,rx-bytes,rx-packets,tx-bytes,tx-packets",
				}...).Then(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch ipsec peers: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.When([]string{
					"/ip/ipsec/policy/print",
					"?disabled=false",
					"?dynamic=false",
					"=.proplist=src-address,dst-address,ph2-state,invalid,active,comment",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"src-address": "192.168.1.1",
								"dst-address": "192.168.2.1",
								"ph2-state":   "established",
								"invalid":     "false",
								"active":      "true",
								"comment":     "comment",
							},
						},
					},
				}, nil)

				routerOSClientMock.RunMock.When([]string{
					"/ip/ipsec/active-peers/print",
					"=.proplist=local-address,remote-address,state,side,uptime,rx-bytes,rx-packets,tx-bytes,tx-packets",
				}...).Then(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"local-address":  "192.168.1.1",
								"remote-address": "192.168.2.1",
								"state":          "established",
								"side":           "responder",
								"uptime":         "a1m40s",
								"rx-bytes":       "b100",
								"rx-packets":     "c10",
								"tx-bytes":       "d10",
								"tx-packets":     "e1",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "tunnel_active", "active ipsec tunnels (active = 1)",
						[]string{"name", "address", "src_address", "dst_address", "ph2_state", "invalid", "comment"},
					),
					prometheus.GaugeValue, 1, "device", "address", "192.168.1.1", "192.168.2.1", "established", "false", "comment",
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
