package config

import (
	"strings"
	"testing"
)

// TestEmptyConfig check that default config created with
// reasonable values
func TestEmptyConfig(t *testing.T) {
	cfg, err := New()
	if err != nil {
		t.Fatalf("Failed to create new config: %s", err)
	}

	if cfg.HTTP.Host != "localhost" {
		t.Fatalf("Expected HTTP host is localhost but found: %s", cfg.HTTP.Host)
	}

	if cfg.HTTP.Port != 80 {
		t.Fatalf("Expected HTTP port is 80 but found: %s", cfg.HTTP.Port)
	}

	if cfg.HTTPS != nil {
		t.Fatalf("Expected HTTPS is not set but found: %s", cfg.HTTPS)
	}

	if cfg.Log.Format != "simple" {
		t.Fatalf("Expected Log format is simple but found: %s", cfg.Log.Format)
	}

	if cfg.Log.Out != "stdout" {
		t.Fatalf("Expected Log out if stdout but found: %s", cfg.Log.Out)
	}

	if cfg.Log.Level != "info" {
		t.Fatalf("Expected Log level is info but found: %s", cfg.Log.Level)
	}

	if len(cfg.Providers) != 1 {
		t.Fatalf("Expected zone provides size is 1 but found: %s", len(cfg.Providers))
	}

	if cfg.Providers[0] != "directory://./zones" {
		t.Fatalf("Expected zone provider is 'directory://./zones' but found: %s", cfg.Providers[0])
	}
}

// TestYamlConfig verifys that config could be red from yaml file and all values
// are setup correctly
func TestYamlConfig(t *testing.T) {
	// Be careful, YAML doesn't allow any spaces...
	cfgText := `
    log:
      format: json
      out: journald
      level: debug

    https:
      iface: 172.14.14.1
      port: 443
      key: /test.key
      crt: /var/run/cerber.cert

    providers:
      - directory:///etc/cerber/zones
      - mongodb://localhost:27017/cerber
    `

	cfg, err := Load(strings.NewReader(cfgText))
	if err != nil {
		t.Fatalf("Failed to load config: %s", err)
	}

	if cfg.HTTP != nil {
		t.Fatalf("Expected HTTP is not set but found: %s", cfg.HTTPS)
	}

	if cfg.HTTPS.Host != "172.14.14.1" {
		t.Fatalf("Expected HTTPS host is 172.14.14.1 but found: %s", cfg.HTTPS.Host)
	}

	if cfg.HTTPS.Port != 443 {
		t.Fatalf("Expected HTTPS port is 443 but found: %s", cfg.HTTPS.Port)
	}

	if cfg.Log.Format != "json" {
		t.Fatalf("Expected Log format is json but found: %s", cfg.Log.Format)
	}

	if cfg.Log.Out != "journald" {
		t.Fatalf("Expected Log out is journald but found: %s", cfg.Log.Out)
	}

	if cfg.Log.Level != "debug" {
		t.Fatalf("Expected Log level is debug but found: %s", cfg.Log.Level)
	}

	if len(cfg.Providers) != 2 {
		t.Fatalf("Expected zone provides size is 2 but found: %s", len(cfg.Providers))
	}

	if cfg.Providers[0] != "directory:///etc/cerber/zones" {
		t.Fatalf("Expected zone provider[0] is 'directory:///etc/cerber/zones' but found: %s", cfg.Providers[0])
	}

	if cfg.Providers[1] != "mongodb://localhost:27017/cerber" {
		t.Fatalf("Expected zone provider[1] is 'mongodb://localhost:27017/cerber' but found: %s", cfg.Providers[1])
	}
}
