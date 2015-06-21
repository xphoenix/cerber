package config

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Certificate extends tls certificate with Yaml unmarshaling methods
type Certificate struct {
	tls.Certificate
}

// UnmarshalYAML decodes tls.Certificate from key/certificate srings
func (c *Certificate) UnmarshalYAML(unmarshal func(interface{}) error) error {
	cfg := struct {
		Key string `yaml:"key"`
		Crt string `yaml:"crt"`
	}{}

	err := unmarshal(&cfg)
	if err != nil {
		return err
	}

	// Decode
	cert, err := tls.LoadX509KeyPair(cfg.Crt, cfg.Key)
	if err != nil {
		return err
	}

	c.Certificate = cert
	return nil
}

// HTTP procotol endpoint configuration
type HTTP struct {
	Host string `yaml:"iface"`
	Port int    `yaml:"port"`
}

// HTTPS protocol endpoint configuration
type HTTPS struct {
	Host string `yaml:"iface"`
	Port int    `yaml:"port"`
	Key  string `yaml:"key"`
	Cert string `yaml:"crt"`
}

// LogConfig describes logging configuration
type LogConfig struct {
	Format string `yaml:"format"`
	Out    string `yaml:"out"`
	Level  string `yaml:"level"`
}

// Config describes main Cerber server configuration. Such things as
// network enpoints, zone providers, logging, e.t.c
type Config struct {
	Realm string `yaml:"realm"`

	// HTTP network endpoint for client communication
	HTTP *HTTP `yaml:"http,omitempty"`

	// HTTPS network endpoint for client communication
	HTTPS *HTTPS `yaml:"https,omitempty"`

	// Logrus logging config
	Log LogConfig `yaml:"log"`

	// Zone providers
	Providers []string `yaml:"providers"`
}

// New creates new config with all values set to defaults. Function creates minimum
// working config which is not safe to be used in production but provides reasonable
// values
func New() (Config, error) {
	return Config{
		HTTP:      &HTTP{Host: "localhost", Port: 80},
		Log:       LogConfig{Format: "simple", Out: "stdout", Level: "info"},
		Providers: []string{"directory://./zones"},
	}, nil
}

// Load reads & parse yaml file from the given input, validates loaded values
// and return final configuration object or error if any
func Load(input io.Reader) (Config, error) {
	cfg := Config{}

	bytes, err := ioutil.ReadAll(input)
	if err != nil {
		return cfg, fmt.Errorf("Failed to read config yaml file: %s", err)
	}

	err2 := yaml.Unmarshal(bytes, &cfg)
	if err2 != nil {
		return cfg, fmt.Errorf("Failed to parse config yaml file: %s", err2)
	}

	// Defaults
	if cfg.HTTP != nil && cfg.HTTP.Port == 0 {
		cfg.HTTP.Port = 80
	}
	if cfg.HTTPS != nil && cfg.HTTPS.Port == 0 {
		cfg.HTTPS.Port = 443
	}

	return cfg, nil
}
