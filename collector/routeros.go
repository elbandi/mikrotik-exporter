package collector

import (
	"crypto/tls"
	"net"

	"github.com/go-routeros/routeros/v3"

	ros "github.com/ogi4i/mikrotik-exporter/routeros"
)

func createClient(device *Device) (ros.Client, error) {
	const (
		defaultAPIPort         = "8728"
		defaultClientQueueSize = 100
	)

	if device.Client.EnableTLS {
		client, err := dialWithTLS(device)
		if err != nil {
			return nil, err
		}

		client.Queue = defaultClientQueueSize
		return client, nil
	}

	if len(device.Port) == 0 {
		device.Port = defaultAPIPort
	}

	client, err := routeros.DialTimeout(
		net.JoinHostPort(device.Address, device.Port),
		device.Username,
		device.Password,
		device.Client.DialTimeout,
	)
	if err != nil {
		return nil, err
	}

	client.Queue = defaultClientQueueSize
	return client, nil
}

func dialWithTLS(device *Device) (*routeros.Client, error) {
	const defaultAPIPortTLS = "8729"

	tlsConfig := &tls.Config{
		InsecureSkipVerify: device.Client.InsecureTLSSkipVerify, // nolint:gosec
	}

	if len(device.Port) == 0 {
		device.Port = defaultAPIPortTLS
	}

	return routeros.DialTLSTimeout(
		net.JoinHostPort(device.Address, device.Port),
		device.Username,
		device.Password,
		tlsConfig,
		device.Client.DialTimeout,
	)
}
