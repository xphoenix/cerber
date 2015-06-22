package zone

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"

	log "github.com/Sirupsen/logrus"
	"github.com/xphoenix/cerber/api"
)

// DirectoryProvider watch given directory for yaml/json zone descriptions and
// load/remove Zones when file changes
type DirectoryProvider struct {
	url *url.URL

	zones map[string]api.Zone
}

// URL returns URI for the current Provider. Protocol must be
// 'direcotry' and path must be absolute path on disk where zone yaml/json
// files are located
func (d *DirectoryProvider) URL() *url.URL {
	return d.url
}

// Start background process that observes filesystem changes
// and refresh zone information.
// Before was started Provider returns no any zones
func (d *DirectoryProvider) Start() error {
	log.Infof("Starting directory zone provider: %s", d.url.Path)

	// TODO: init inotify
	// It is important to start inotify first to not skip updates happens in between
	// directory read & inotify initialization

	files, err := ioutil.ReadDir(d.url.Path)
	if err != nil {
		return fmt.Errorf("Failed to list directory: %s", d.url.Path)
	}

	// Load all zones
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		log.Infof("Loading zone file: %s", f.Name())
		fullPath := filepath.Join(d.url.Path, f.Name())

		fd, err := os.Open(fullPath)
		if err != nil {
			return fmt.Errorf("Failed to open file: %s", fullPath)
		}

		bytes, err := ioutil.ReadAll(fd)
		if err != nil {
			return fmt.Errorf("Failed to read file: %s", fullPath)
		}

		z := yamlZone{}
		parseErr := yaml.Unmarshal(bytes, &z)
		if parseErr != nil {
			return fmt.Errorf("Failed to parse file: %s %s", fullPath, parseErr)
		}

		i, err := d.FindZone(z.Name())
		if err == nil {
			return fmt.Errorf("Found duplicated zone: %s (%s)", i.Name(), i.Description())
		}

		// Save zone
		d.registerZone(&z)
	}
	return nil
}

// Stop kill background process that is watching for filesystem
// changes and refreshing zone information. If process wasn't
// started then method returns without any actual work
// After was stopped Provider returns no zones
func (d *DirectoryProvider) Stop() error {
	return nil
}

// IsOnline returns true if provider was started successfully and running,
// without errors. If method returns true then zone information available
// for readers
func (d *DirectoryProvider) IsOnline() (bool, error) {
	return false, nil
}

// FindZone returns first available zone known by the current Provider and has given name
func (d *DirectoryProvider) FindZone(name string) (api.Zone, error) {
	name = strings.ToUpper(name)
	z, ok := d.zones[name]
	if !ok {
		return nil, fmt.Errorf("There is no zone with the given name: %s", name)
	}

	return z, nil
}

func (d *DirectoryProvider) registerZone(z api.Zone) {
	name := strings.ToUpper(z.Name())
	d.zones[name] = z
}
