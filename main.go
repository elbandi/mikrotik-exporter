package main

import (
	"bytes"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/ogi4i/mikrotik-exporter/collector"
	"github.com/ogi4i/mikrotik-exporter/collector/bgp"
	"github.com/ogi4i/mikrotik-exporter/collector/bridge/firewall"
	"github.com/ogi4i/mikrotik-exporter/collector/bridge/hosts"
	"github.com/ogi4i/mikrotik-exporter/collector/capsman"
	"github.com/ogi4i/mikrotik-exporter/collector/conntrack"
	"github.com/ogi4i/mikrotik-exporter/collector/dhcp"
	"github.com/ogi4i/mikrotik-exporter/collector/dhcp_ipv6"
	"github.com/ogi4i/mikrotik-exporter/collector/dns"
	"github.com/ogi4i/mikrotik-exporter/collector/firewall"
	"github.com/ogi4i/mikrotik-exporter/collector/firmware"
	"github.com/ogi4i/mikrotik-exporter/collector/health"
	interface_collector "github.com/ogi4i/mikrotik-exporter/collector/interface"
	"github.com/ogi4i/mikrotik-exporter/collector/interface/ethernet"
	"github.com/ogi4i/mikrotik-exporter/collector/interface/lte"
	"github.com/ogi4i/mikrotik-exporter/collector/interface/sfp"
	"github.com/ogi4i/mikrotik-exporter/collector/interface/wlan"
	"github.com/ogi4i/mikrotik-exporter/collector/ip_pool"
	"github.com/ogi4i/mikrotik-exporter/collector/ipsec"
	"github.com/ogi4i/mikrotik-exporter/collector/kid_control"
	"github.com/ogi4i/mikrotik-exporter/collector/netwatch"
	"github.com/ogi4i/mikrotik-exporter/collector/ospf_neighbors"
	"github.com/ogi4i/mikrotik-exporter/collector/poe"
	"github.com/ogi4i/mikrotik-exporter/collector/ppp"
	"github.com/ogi4i/mikrotik-exporter/collector/resource"
	"github.com/ogi4i/mikrotik-exporter/collector/routes"
	"github.com/ogi4i/mikrotik-exporter/collector/wireguard_peers"
	"github.com/ogi4i/mikrotik-exporter/collector/wireless/stations"
	"github.com/ogi4i/mikrotik-exporter/collector/wireless/w60g"
	"github.com/ogi4i/mikrotik-exporter/config"
)

var (
	address               = flag.String("address", fromEnv("MIKROTIK_ADDRESS", ""), "address of the device")
	configFile            = flag.String("config-file", fromEnv("MIKROTIK_EXPORTER_CONFIG_FILE", ""), "config file to load")
	deviceName            = flag.String("name", fromEnv("MIKROTIK_DEVICE_NAME", ""), "name of the device")
	logFormat             = flag.String("log-format", fromEnv("LOG_FORMAT", "json"), "log format text or json (default json)")
	logLevel              = flag.String("log-level", fromEnv("LOG_LEVEL", "info"), "log level")
	metricsPath           = flag.String("path", fromEnv("MIKROTIK_EXPORTER_PATH", "/metrics"), "path to answer requests on")
	username              = flag.String("username", fromEnv("MIKROTIK_USERNAME", ""), "username for authentication with single device")
	password              = flag.String("password", fromEnv("MIKROTIK_PASSWORD", ""), "password for authentication for single device")
	devicePort            = flag.String("device-port", fromEnv("MIKROTIK_PORT", "8728"), "port for single device")
	port                  = flag.String("port", fromEnv("MIKROTIK_EXPORTER_PORT", "9436"), "port number to listen on")
	timeout               = flag.Duration("timeout", 0, "timeout when connecting to devices")
	enableTLS             = flag.Bool("enable-tls", false, "enable TLS to connect to routers")
	insecureTLSSkipVerify = flag.Bool("insecure-tls-skip-verify", false, "skips verification of server certificate when using TLS (not recommended)")

	defaultCollectors = []collector.FeatureCollector{
		interface_collector.NewCollector(),
		resource.NewCollector(),
	}

	errInvalidParamForSingleDevice = errors.New("missing required param for single device configuration")
)

func main() {
	flag.Parse()

	configureLog()

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Could not load config: %v", err)
	}

	mustStartServer(cfg)
}

func fromEnv(key, defaultValue string) string {
	if v := os.Getenv(key); len(v) != 0 {
		return v
	}

	return defaultValue
}

func configureLog() {
	ll, err := log.ParseLevel(*logLevel)
	if err != nil {
		panic(err)
	}

	log.SetLevel(ll)

	if *logFormat == "text" {
		log.SetFormatter(&log.TextFormatter{})
	} else {
		log.SetFormatter(&log.JSONFormatter{})
	}
}

func loadConfig() (*config.Config, error) {
	if *configFile != "" {
		return loadConfigFromFile()
	}

	return loadConfigFromFlags()
}

func loadConfigFromFile() (*config.Config, error) {
	b, err := os.ReadFile(*configFile)
	if err != nil {
		return nil, err
	}

	return config.Load(bytes.NewReader(b))
}

func loadConfigFromFlags() (*config.Config, error) {
	if len(*deviceName) == 0 ||
		len(*address) == 0 ||
		len(*username) == 0 ||
		len(*password) == 0 {
		return nil, errInvalidParamForSingleDevice
	}

	return &config.Config{
		Devices: []*config.Device{
			{
				Name:     *deviceName,
				Address:  *address,
				Username: *username,
				Password: *password,
				Port:     *devicePort,
				Client: &config.Client{
					DialTimeout:           *timeout,
					EnableTLS:             *enableTLS,
					InsecureTLSSkipVerify: *insecureTLSSkipVerify,
				},
			},
		},
	}, nil
}

func mustStartServer(cfg *config.Config) {
	http.Handle(*metricsPath, mustCreateMetricsHandler(cfg))

	http.HandleFunc("/live", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>
			<head><title>Mikrotik Exporter</title></head>
			<body>
			<h1>Mikrotik Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})

	log.Infof("Listening on: %s", *port)

	srv := http.Server{
		Addr:         ":" + *port,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("failed to start server: %v", err)
	}
}

func mustCreateMetricsHandler(cfg *config.Config) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewBuildInfoCollector(),
		collector.NewMikrotikCollector(
			buildDevicesFromConfig(cfg),
			collector.WithCollectors(append(buildCollectors(cfg.Features), defaultCollectors...)...),
		),
	)

	return promhttp.HandlerFor(
		registry,
		promhttp.HandlerOpts{
			ErrorLog:      log.New(),
			ErrorHandling: promhttp.ContinueOnError,
		},
	)
}

func buildCollectors(features *config.Features) []collector.FeatureCollector {
	if features == nil {
		return nil
	}

	var collectors []collector.FeatureCollector

	if features.BGP {
		collectors = append(collectors, bgp.NewCollector())
	}

	if features.BridgeFirewall {
		collectors = append(collectors, bridge_firewall.NewCollector())
	}

	if features.Routes {
		collectors = append(collectors, routes.NewCollector(features.RoutesIPv6))
	}

	if features.DHCP {
		collectors = append(collectors, dhcp.NewCollector())
	}

	if features.DHCPIPv6 {
		collectors = append(collectors, dhcp_ipv6.NewCollector())
	}

	if features.DNS {
		collectors = append(collectors, dns.NewCollector())
	}

	if features.Firewall {
		collectors = append(collectors, firewall.NewCollector())
	}

	if features.Firmware {
		collectors = append(collectors, firmware.NewCollector())
	}

	if features.Health {
		collectors = append(collectors, health.NewCollector())
	}

	if features.PoE {
		collectors = append(collectors, poe.NewCollector())
	}

	if features.PPP {
		collectors = append(collectors, ppp.NewCollector())
	}

	if features.IPPools {
		collectors = append(collectors, ip_pool.NewCollector())
	}

	if features.SFP {
		collectors = append(collectors, sfp.NewCollector())
	}

	if features.W60G {
		collectors = append(collectors, w60g.NewCollector())
	}

	if features.WLANStations {
		collectors = append(collectors, stations.NewCollector())
	}

	if features.CAPsMAN {
		collectors = append(collectors, capsman.NewCollector())
	}

	if features.WLANInterfaces {
		collectors = append(collectors, wlan.NewCollector())
	}

	if features.Ethernet {
		collectors = append(collectors, ethernet.NewCollector())
	}

	if features.IPSec {
		collectors = append(collectors, ipsec.NewCollector())
	}

	if features.OSPFNeighbors {
		collectors = append(collectors, ospf_neighbors.NewCollector())
	}

	if features.LTE {
		collectors = append(collectors, lte.NewCollector())
	}

	if features.Netwatch {
		collectors = append(collectors, netwatch.NewCollector())
	}

	if features.Conntrack {
		collectors = append(collectors, conntrack.NewCollector())
	}

	if features.BridgeHosts {
		collectors = append(collectors, bridge_hosts.NewCollector())
	}

	if features.WireguardPeers {
		collectors = append(collectors, wireguard_peers.NewCollector())
	}

	if features.KidControl {
		collectors = append(collectors, kid_control.NewCollector())
	}

	return collectors
}

func buildDevicesFromConfig(cfg *config.Config) []*collector.Device {
	res := make([]*collector.Device, 0, len(cfg.Devices))
	for _, d := range cfg.Devices {
		res = append(res, &collector.Device{
			Name:       d.Name,
			Address:    d.Address,
			Port:       d.Port,
			Username:   d.Username,
			Password:   d.Password,
			Client:     buildClient(cfg.Client, d.Client),
			DNSRecord:  buildDNSRecord(d),
			Collectors: buildCollectors(d.Features),
		})
	}
	return res
}

func buildClient(appLevelClient, deviceLevelClient *config.Client) collector.Client {
	const defaultDialTimeout = 5 * time.Second

	switch {
	case appLevelClient == nil && deviceLevelClient == nil:
		return collector.Client{
			DialTimeout:           defaultDialTimeout,
			EnableTLS:             false,
			InsecureTLSSkipVerify: false,
		}
	case deviceLevelClient == nil:
		return collector.Client{
			DialTimeout:           appLevelClient.DialTimeout,
			EnableTLS:             appLevelClient.EnableTLS,
			InsecureTLSSkipVerify: appLevelClient.InsecureTLSSkipVerify,
		}
	default:
		return collector.Client{
			DialTimeout:           deviceLevelClient.DialTimeout,
			EnableTLS:             deviceLevelClient.EnableTLS,
			InsecureTLSSkipVerify: deviceLevelClient.InsecureTLSSkipVerify,
		}
	}
}

func buildDNSRecord(d *config.Device) *collector.Record {
	if d.DNSRecord == nil {
		return nil
	}

	return &collector.Record{
		Name:          d.DNSRecord.Record,
		ServerAddress: buildServerAddress(d.DNSRecord.Server),
	}
}

func buildServerAddress(s *config.DNSServer) string {
	if s == nil {
		return ""
	}

	return net.JoinHostPort(s.Address, s.Port)
}
