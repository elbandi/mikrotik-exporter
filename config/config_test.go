package config

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestShouldParse(t *testing.T) {
	r := require.New(t)
	t.Parallel()

	t.Run("should parse", func(t *testing.T) {
		cfg, err := Load(bytes.NewReader(loadTestFile(r)))
		r.NoError(err)

		r.Len(cfg.Devices, 2)
		r.Equal(&Device{
			Name:     "test1",
			Address:  "192.168.1.1",
			Username: "foo",
			Password: "bar",
			Client: &Client{
				DialTimeout:           time.Second,
				EnableTLS:             true,
				InsecureTLSSkipVerify: true,
			},
		}, cfg.Devices[0])
		r.Equal(&Device{
			Name:     "test2",
			Address:  "192.168.2.1",
			Username: "test",
			Password: "123",
			DNSRecord: &SrvRecord{
				Record: "test.fqdn.com",
				Server: &DNSServer{
					Address: "1.1.1.1",
				},
			},
		}, cfg.Devices[1])

		r.True(cfg.Features.BGP)
		r.True(cfg.Features.DHCP)
		r.True(cfg.Features.DHCPIPv6)
		r.True(cfg.Features.Firewall)
		r.True(cfg.Features.Firmware)
		r.True(cfg.Features.Health)
		r.True(cfg.Features.IPPools)
		r.True(cfg.Features.Routes)
		r.True(cfg.Features.RoutesIPv6)
		r.True(cfg.Features.Ethernet)
		r.True(cfg.Features.PoE)
		r.True(cfg.Features.SFP)
		r.True(cfg.Features.WLANStations)
		r.True(cfg.Features.CAPsMAN)
		r.True(cfg.Features.WLANInterfaces)
		r.True(cfg.Features.IPSec)
		r.True(cfg.Features.OSPFNeighbors)
		r.True(cfg.Features.LTE)
		r.True(cfg.Features.Netwatch)
		r.True(cfg.Features.Conntrack)
		r.True(cfg.Features.BridgeHosts)
		r.True(cfg.Features.WireguardPeers)
	})

	t.Run("invalid yaml", func(t *testing.T) {
		cfg, err := Load(bytes.NewReader([]byte(`devices:
  name: test1
  address: 192.168.1.1`)))
		r.EqualError(err, "failed to unmarshal bytes to config: yaml: unmarshal errors:\n  line 2: cannot unmarshal !!map into []*config.Device")
		r.Nil(cfg)
	})
}

func loadTestFile(r *require.Assertions) []byte {
	b, err := os.ReadFile("../testdata/config.test.yml")
	r.NoError(err)

	return b
}
