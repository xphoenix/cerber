package rest

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/ant0ine/go-json-rest/rest"
)

// UnauthorizedJWT is the rest endpoint that return 401 error with JWT realm
func UnauthorizedJWT(writer rest.ResponseWriter, request *rest.Request, err error) {
	cerber := Cerber(request)
	var realm = base64.StdEncoding.EncodeToString([]byte(cerber.Realm))
	unanauthorized(writer, request, fmt.Sprintf("JWT realm=%s", realm), err)
}

// UnauthorizedBasic is the rest endpoint that return 401 error with Basic realm
func UnauthorizedBasic(writer rest.ResponseWriter, request *rest.Request, err error) {
	cerber := Cerber(request)
	var realm = base64.StdEncoding.EncodeToString([]byte(cerber.Realm))
	unanauthorized(writer, request, fmt.Sprintf("Basic realm=%s", realm), err)
}

func unanauthorized(writer rest.ResponseWriter, request *rest.Request, realm string, err error) {
	logger := Logger(request)
	logger.WithField("reason", err).Error("Request unauthorized")

	writer.Header().Set("WWW-Authenticate", realm)
	rest.Error(writer, "Not Authorized", http.StatusUnauthorized)
}
