package config

import (
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"
)

type (
	// Config - represents the global configuration of the exporter
	Config struct {
		// Devices - represents a list of device configurations
		Devices []*Device `yaml:"devices"`
		// Client - represents app level RouterOS client configuration, optional
		Client *Client `yaml:"client,omitempty"`
		// Features - represents app level feature flags, optional
		Features *Features `yaml:"features,omitempty"`
	}

	// Features - represents feature flags for the exporter
	Features struct {
		// BGP - enables BGP metrics collection
		BGP bool `yaml:"bgp,omitempty"`
		// BridgeFirewall - enables bridge firewall metrics collection
		BridgeFirewall bool `yaml:"bridge_firewall,omitempty"`
		// DHCP - enables DHCP server metrics collection
		DHCP bool `yaml:"dhcp,omitempty"`
		// DHCPIPv6 - enables DHCP IPv6 server metrics collection
		DHCPIPv6 bool `yaml:"dhcp_ipv6,omitempty"`
		// DNS - enables DNS server metrics collection
		DNS bool `yaml:"dns,omitempty"`
		// Firewall - enables IPv4 firewall metrics collection
		Firewall bool `yaml:"firewall,omitempty"`
		// Firmware - enables firmware metrics collection
		Firmware bool `yaml:"firmware,omitempty"`
		// Health - enables health metrics collection
		Health bool `yaml:"health,omitempty"`
		// Routes - enables IPv4 routes metrics collection
		Routes bool `yaml:"routes,omitempty"`
		// PoE - enables PoE metrics collection
		PoE bool `yaml:"poe,omitempty"`
		// PPP - enables PPP metrics collection
		PPP bool `yaml:"ppp,omitempty"`
		// IPPools - enables IP pools metrics collection
		IPPools bool `yaml:"ip_pools,omitempty"`
		// SFP - enables SFP modules metrics collection
		SFP bool `yaml:"sfp,omitempty"`
		// W60G - enables wireless 60G metrics collection
		W60G bool `yaml:"w60g,omitempty"`
		// WLANStations - enables WLAN stations metrics collection
		WLANStations bool `yaml:"wlan_stations,omitempty"`
		// CAPsMAN - enables CAPsMAN metrics collection
		CAPsMAN bool `yaml:"capsman,omitempty"`
		// WLANInterfaces - enables WLAN interfaces metrics collection
		WLANInterfaces bool `yaml:"wlan,omitempty"`
		// Ethernet - enables interface ethernet metrics collection
		Ethernet bool `yaml:"ethernet,omitempty"`
		// IPSec - enables IPSec metrics collection
		IPSec bool `yaml:"ipsec,omitempty"`
		// OSPFNeighbors - enables OSPF neighbors metrics collection
		OSPFNeighbors bool `yaml:"ospf_neighbors,omitempty"`
		// LTE - enables LTE interface metrics collection
		LTE bool `yaml:"lte,omitempty"`
		// Netwatch - enables netwatch metrics collection
		Netwatch bool `yaml:"netwatch,omitempty"`
		// Conntrack - enables firewall conntrack metrics collection
		Conntrack bool `yaml:"conntrack,omitempty"`
		// BridgeHosts - enables bridge hosts metrics collection
		BridgeHosts bool `yaml:"bridge_hosts,omitempty"`
		// WireguardPeers - enables wireguard peers metrics collection
		WireguardPeers bool `yaml:"wireguard_peers,omitempty"`
		// KidControl - enables Kid Control metrics collection
		KidControl bool `yaml:"kid_control,omitempty"`
	}

	// Device - represents a target device configuration
	Device struct {
		// Name - represents device Name
		Name string `yaml:"name"`
		// Address - represents device Address (IP or FQDN), optional
		Address string `yaml:"address,omitempty"`
		// DNSRecord - represents device SRV DNS record configuration, optional
		DNSRecord *SrvRecord `yaml:"dns_record,omitempty"`
		// Username - represents device authentication username
		Username string `yaml:"username"`
		// Password - represents device authentication password
		Password string `yaml:"password"`
		// Port - represents which port to use when establishing connection to device, optional
		Port string `yaml:"port,omitempty"`
		// Client - represents device level RouterOS client configuration, optional
		Client *Client `yaml:"client,omitempty"`
		// Features - represents device level feature flags, optional
		Features *Features `yaml:"features,omitempty"`
	}

	// SrvRecord - represents a SRV DNS record configuration
	SrvRecord struct {
		// Record - represents SRV DNS record
		Record string `yaml:"record"`
		// Server - represents DNS server configuration, optional
		Server *DNSServer `yaml:"server,omitempty"`
	}

	// DNSServer - represents a DNS server configuration
	DNSServer struct {
		// Address - represents DNS server IP address
		Address string `yaml:"address"`
		// Port - represents DNS server port
		Port string `yaml:"port"`
	}

	// Client - represents a RouterOS client configuration
	Client struct {
		// DialTimeout - timeout for net.Dial operation, optional
		DialTimeout time.Duration `yaml:"dial_timeout,omitempty"`
		// EnableTLS - enables TLS when establishing connection to RouterOS device, optional
		EnableTLS bool `yaml:"enable_tls,omitempty"`
		// InsecureTLSSkipVerify - enables insecure TLS (skip server certificate verification), optional
		InsecureTLSSkipVerify bool `yaml:"insecure_tls_skip_verify,omitempty"`
	}
)

// Load - reads bytes from io.Reader and parses as YAML into Config
func Load(r io.Reader) (*Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read bytes from reader: %w", err)
	}

	var cfg Config
	if err = yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bytes to config: %w", err)
	}

	return &cfg, nil
}
