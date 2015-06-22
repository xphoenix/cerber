package api

import "net/url"

// Provider represents source of zone descriptions, such as filesystem or database
type Provider interface {
	URL() *url.URL
	FindZone(zone string) (Zone, error)
	IsOnline() (bool, error)
	Start() error
	Stop() error
}
