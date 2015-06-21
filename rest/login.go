package rest

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"

	log "github.com/Sirupsen/logrus"

	"github.com/ant0ine/go-json-rest/rest"
)

type permission struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

type loginResponse struct {
	Token *string `json:"token"`
}

// BasicLogin is a rest handler function that generate JWT token based on
// QueryString and Basic HTTP authentification headers
func BasicLogin(writer rest.ResponseWriter, request *rest.Request) {
	// Get cerber instance
	logger, c := Logger(request), Cerber(request)

	// Check header
	authHeader := request.Header.Get("Authorization")
	if authHeader == "" {
		UnauthorizedBasic(writer, request, errors.New("Basic qutorization is required"))
		return
	}

	// Decode user credentials
	providedUserID, providedPassword, err := decodeBasicAuthHeader(authHeader)
	if err != nil {
		UnauthorizedBasic(writer, request, err)
		return
	}

	// Parse query string for options
	vals := request.URL.Query()
	service := vals["service"]
	if len(service) == 0 {
		service = request.Header["Host"]
		if len(service) == 0 {
			service = []string{""}
		}
	}

	scope := vals["scope"]
	if len(scope) == 0 {
		scope = []string{""}
	}

	// Use cerber to login
	logger.WithFields(log.Fields{
		"zone":     service,
		"user":     providedUserID,
		"password": len(providedPassword),
	}).Debug("Authentificating user in zone")

	z, err := c.FindZone(service[0])
	if err != nil {
		UnauthorizedBasic(writer, request, err)
		return
	}

	providedPassword, err = z.HashPassword(providedPassword)
	if err != nil {
		UnauthorizedBasic(writer, request, err)
		return
	}

	// Query zone for user and check password
	actions, err := c.Authorize(z, providedUserID, providedPassword)
	if err != nil {
		UnauthorizedBasic(writer, request, err)
		return
	}

	access, err := createAccessSet(actions)
	if err != nil {
		UnauthorizedBasic(writer, request, err)
		return
	}

	// Convert actions into docker distribution access list
	// Transform raw actions into the docker access list format
	claims := map[string]interface{}{
		"iss":    c.Realm,
		"sub":    providedUserID,
		"aud":    z.Name(),
		"access": access,
	}

	// TODO: pass zone to encryptor
	token, err := c.GenerateToken(service[0], providedUserID, providedPassword, scope[0], claims)
	if err != nil {
		UnauthorizedBasic(writer, request, err)
		return
	}

	// Setup request context
	request.Env["REMOTE_USER"] = providedUserID
	request.Env["TOKEN"] = token

	// Write response
	writer.WriteJson(loginResponse{token})
}

// Parse Basic auth header value
func decodeBasicAuthHeader(header string) (user string, password string, err error) {
	parts := strings.SplitN(header, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Basic") {
		return "", "", errors.New("Invalid authentication")
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", errors.New("Invalid base64")
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		return "", "", errors.New("Invalid authentication")
	}

	return creds[0], creds[1], nil
}

func createAccessSet(actions []string) ([]permission, error) {
	perm := permission{"repository", "", make([]string, 0, 1)}
	result := make([]permission, 0, 2)

	sort.Strings(actions)
	for _, a := range actions {
		idx := strings.Index(a, ":")
		if idx == -1 {
			return nil, fmt.Errorf("Invalid action format: '%s'", a)
		}

		name, action := a[0:idx], a[idx+1:]
		if name == "" || action == "" {
			return nil, fmt.Errorf("Invalid action format: '%s'", a)
		}

		if perm.Name == "" || perm.Name == name {
			perm.Name = name
			perm.Actions = append(perm.Actions, action)
		} else {
			result = append(result, perm)
			perm = permission{"repository", name, []string{action}}
		}
	}

	result = append(result, perm)
	return result, nil
}
