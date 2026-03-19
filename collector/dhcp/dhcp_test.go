package dhcp

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

func Test_dhcpLeaseCollector_Name(t *testing.T) {
	r := require.New(t)

	c := NewCollector()

	r.Equal("dhcp_lease", c.Name())
}

func Test_dhcpLeaseCollector_Describe(t *testing.T) {
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
		metrics.BuildMetricDescription(prefix, "expires_after", "dhcp lease expires after seconds",
			[]string{"name", "address", "active_mac_address", "server", "status", "active_address", "hostname"},
		),
	}, got)
}

func Test_dhcpLeaseCollector_Collect(t *testing.T) {
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
						"/ip/dhcp-server/lease/print",
						"=.proplist=active-mac-address,server,status,expires-after,active-address,host-name",
					}, sentence)
				}).Return(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"active-mac-address": "active-mac-address",
								"server":             "server",
								"status":             "bound",
								"expires-after":      "1m40s",
								"active-address":     "192.168.1.1",
								"host-name":          "host-name",
							},
						},
					},
				}, nil)
			},
			want: []prometheus.Metric{
				prometheus.MustNewConstMetric(
					metrics.BuildMetricDescription(prefix, "expires_after", "dhcp lease expires after seconds",
						[]string{"name", "address", "active_mac_address", "server", "status", "active_address", "hostname"},
					),
					prometheus.GaugeValue, 100, "device", "address", "active-mac-address", "server",
					"bound", "192.168.1.1", `"host-name"`,
				),
			},
		},
		{
			name: "fetch error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/ip/dhcp-server/lease/print",
						"=.proplist=active-mac-address,server,status,expires-after,active-address,host-name",
					}, sentence)
				}).Return(nil, errors.New("some fetch error"))
			},
			errWant: "failed to fetch dhcp leases: some fetch error",
		},
		{
			name: "parse error",
			setMocks: func() {
				routerOSClientMock.RunMock.Inspect(func(sentence ...string) {
					r.Equal([]string{
						"/ip/dhcp-server/lease/print",
						"=.proplist=active-mac-address,server,status,expires-after,active-address,host-name",
					}, sentence)
				}).Return(&routeros.Reply{
					Re: []*proto.Sentence{
						{
							Map: map[string]string{
								"active-mac-address": "active-mac-address",
								"server":             "server",
								"status":             "bound",
								"expires-after":      "a1m20s",
								"active-address":     "192.168.1.1",
								"host-name":          "host-name",
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
