package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/ant0ine/go-json-rest/rest"

	"github.com/coreos/go-systemd/journal"
	"github.com/wercker/journalhook"
	"github.com/xphoenix/cerber/api"
	"github.com/xphoenix/cerber/config"
	handlers "github.com/xphoenix/cerber/rest"
	"github.com/xphoenix/cerber/zone"
)

func main() {
	// Load configuration file
	cfg, err := loadConfig()
	if err != nil {
		logrus.Panicf("Failed to load config: %s", err)
	}

	// Create applicaton
	cerber, err := api.New(cfg.Realm)
	if err != nil {
		logrus.Panicf("Failed to create Cerber instance: %s", err)
	}

	// Configure server
	configureLogger(cfg.Log)
	configureZoneProviders(cerber, cfg.Providers)

	api := rest.NewApi()
	configureAPI(api, cerber)

	// Spin up HTTP server
	done := make(chan bool)
	handler := api.MakeHandler()

	unhandled := logrus.StandardLogger().Writer()
	defer unhandled.Close()

	if cfg.HTTP != nil {
		go func() {
			srv := http.Server{
				Addr:     fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port),
				Handler:  handler,
				ErrorLog: log.New(unhandled, "", 0),
			}

			logrus.WithField("address", srv.Addr).Info("Start HTTP interface")
			err := srv.ListenAndServe()

			logrus.WithField("reason", err).Error("HTTP server stopped")
			done <- true
		}()
	}

	// Spinup HTTP server
	if cfg.HTTPS != nil {
		go func() {
			srv := http.Server{
				Addr:     fmt.Sprintf("%s:%d", cfg.HTTPS.Host, cfg.HTTPS.Port),
				Handler:  handler,
				ErrorLog: log.New(unhandled, "", 0),
			}

			logrus.WithField("address", srv.Addr).Info("Start HTTPS interface")
			err := srv.ListenAndServeTLS(cfg.HTTPS.Cert, cfg.HTTPS.Key)

			logrus.WithField("reason", err).Error("HTTPS server stopped")
			done <- true
		}()
	}

	// Wit until one of interface dies
	if cfg.HTTP != nil || cfg.HTTPS != nil {
		<-done
	}
}

func loadConfig() (config.Config, error) {
	if len(os.Args) != 2 {
		return config.Config{}, errors.New("Expected single command line argument - config file path")
	}

	// Load configuration
	file, err := os.Open(os.Args[1])
	if err != nil {
		return config.Config{}, fmt.Errorf("Failed to open file: %s", err)
	}

	cfg, err := config.Load(file)
	if err != nil {
		return cfg, fmt.Errorf("Failed to load config: %s", err)
	}

	return cfg, nil
}

func configureLogger(cfg config.LogConfig) {
	// Setup output
	switch strings.ToUpper(cfg.Out) {
	case "CONSOLE":
		logrus.SetOutput(os.Stdout)
	case "JOURNALD":
		if !journal.Enabled() {
			logrus.Panic("Journald is not available")
		}
		logrus.AddHook(&journalhook.JournalHook{})
		logrus.SetOutput(ioutil.Discard)
	default:
		logrus.Panicf("Unknown logger output: %s", cfg.Out)
	}

	// Setup format
	switch strings.ToUpper(cfg.Format) {
	case "JSON":
		logrus.SetFormatter(&logrus.JSONFormatter{})
	case "TEXT":
		logrus.SetFormatter(&logrus.TextFormatter{})
	default:
		logrus.Panicf("Unknown logger format: %s", cfg.Format)
	}

	// Setup minimum level
	level, err := logrus.ParseLevel(strings.ToLower(cfg.Level))
	if err != nil {
		logrus.Panicf("Unknown logger level: %s", cfg.Level)
	}
	logrus.SetLevel(level)
}

func configureZoneProviders(c *api.Cerber, cfg []string) {
	for _, location := range cfg {
		// Resolve location from config
		p, err := zone.NewProvider(location)
		if err != nil {
			logrus.Warnf("Error creating provider for location '%s': %s", location, err)
			continue
		}

		// Initializate new provider
		err2 := p.Start()
		if err2 != nil {
			logrus.Warnf("Failed to start zone provider '%s': %s", location, err2)
			continue
		}

		// Register provider in the Cerber instance
		c.AddProvider(p)
	}
}

func configureAPI(api *rest.Api, cerber *api.Cerber) {
	// Create middleware chains
	api.Use(
		&handlers.LogMiddleware{Logger: logrus.StandardLogger()},
		// Authentification & Authorization middleware to control access to API endpoint
		&handlers.CerberMiddleware{
			Cerber: cerber,

			// Allow login to bypass JWT auth
			ExceptionSelector: func(request *rest.Request) (bypass bool, err error) {
				return request.URL.Path == "/login", nil
			},

			// Allow all request which has JWT token
			Authorizator: nil,
		},
		&rest.TimerMiddleware{},
		&rest.RecorderMiddleware{},
		&rest.PoweredByMiddleware{},
		&rest.RecoverMiddleware{
			EnableResponseStackTrace: true,
		},
		&rest.JsonIndentMiddleware{},
		&rest.ContentTypeCheckerMiddleware{},
		&rest.GzipMiddleware{},
	)

	// API definition
	router, _ := rest.MakeRouter(
		rest.Get("/login", handlers.BasicLogin),
		rest.Get("/validate", handlers.ValidateToken),
		rest.Get("/refresh", handlers.RefreshToken),
	)

	api.SetApp(router)
}
