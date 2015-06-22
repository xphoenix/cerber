package zone

import (
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/xphoenix/cerber/api"
)

// NewProvider creates Zone Provider object based on given URL.
func NewProvider(loc string) (api.Provider, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse Cerber Zone Provider URL: %s", err)
	}

	switch u.Scheme {
	case "directory":
		// Check that URL has no hash & query
		if u.Fragment != "" || len(u.Query()) > 0 {
			return nil, fmt.Errorf("Directory URL shouldn't has fragmanet or query parts: %s", u.String())
		}

		// Check if path exists and is a directory
		// TODO: permission checks?
		fileInfo, err := os.Stat(u.Path)
		if err != nil {
			return nil, fmt.Errorf("Error during access specified path: %s", err)
		} else if !fileInfo.IsDir() {
			return nil, fmt.Errorf("Given path is not directory: %s", u.Path)
		}

		return &DirectoryProvider{
			url:   u,
			zones: make(map[string]api.Zone, 0),
		}, nil

	case "mongodb":
		return &MongodbProvider{
			url:   u,
			zones: make([]api.Zone, 0),
		}, nil

	default:
		return nil, errors.New("Unknown Cerber Zone Provider schema: " + u.Scheme)
	}
}
