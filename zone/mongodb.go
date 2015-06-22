package zone

import (
	"net/url"

	"github.com/xphoenix/cerber/api"
)

// MongodbProvider loads zone, user, groups and keys information
// from the mongodb instance
type MongodbProvider struct {
	url *url.URL

	zones []api.Zone
}

// URL returns URI for the current Provider. Protocol must be
// 'direcotry' and path must be absolute path on disk where zone yaml/json
// files are located
func (m *MongodbProvider) URL() *url.URL {
	return m.url
}

// Start background process that observes filesystem changes
// and refresh zone information.
// Before was started Provider returns no any zones
func (m *MongodbProvider) Start() error {
	return nil
}

// Stop kill background process that is watching for filesystem
// changes and refreshing zone information. If process wasn't
// started then method returns without any actual work
// After was stopped Provider returns no zones
func (m *MongodbProvider) Stop() error {
	return nil
}

// IsOnline returns true if provider was started successfully and running,
// without errors. If method returns true then zone information available
// for readers
func (m *MongodbProvider) IsOnline() (bool, error) {
	return false, nil
}

// FindZone returns all available zones known by the current Provider
func (m *MongodbProvider) FindZone(zone string) (api.Zone, error) {
	return nil, nil
}
