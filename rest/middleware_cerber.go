package rest

import (
	"errors"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/dgrijalva/jwt-go"
	"github.com/xphoenix/cerber/api"
)

// CerberMiddleware is go-rest middlware that protect resources with JWT tokens
type CerberMiddleware struct {
	// Cerber instance to create/validate tokens
	Cerber *api.Cerber

	// ExceptionSelector is a function allows to bypass token check
	// Could be nil in that case all requests require a valid JWT token to be executed
	ExceptionSelector func(request *rest.Request) (bypass bool, err error)

	// Authorizator allow request to be processed with given token
	// Could be nil in that case all request contains a valid JWT token are allowed
	Authorizator func(token *jwt.Token, request *rest.Request) (allowed bool, err error)
}

// AllowAll is authorization function that allows all actions for any token
func AllowAll(token *jwt.Token, request *rest.Request) (allowed bool, err error) {
	return true, nil
}

// NullExceptionSelector force all request to be guarded by JWT token
func NullExceptionSelector(request *rest.Request) (bypass bool, err error) {
	return false, nil
}

// MiddlewareFunc makes Cerber implement the Middleware interface.
func (mw *CerberMiddleware) MiddlewareFunc(handler rest.HandlerFunc) rest.HandlerFunc {

	if mw.Cerber == nil {
		log.Fatal("Cerber instance is required")
	}

	if mw.Authorizator == nil {
		log.Warnf("Authorizator is not set, use ALLOW_ALL instance")
		mw.Authorizator = AllowAll
	}

	if mw.ExceptionSelector == nil {
		mw.ExceptionSelector = NullExceptionSelector
	}

	return func(writer rest.ResponseWriter, request *rest.Request) {
		// Setup global constants
		logger := Logger(request)
		request.Env["CERBER"] = mw.Cerber

		// Check if request could bypass checks
		bypass, err := mw.ExceptionSelector(request)
		if err != nil {
			logger.Fatal("Failed to call user suplied ExceptionSelector")
		}

		// Check token if required
		if !bypass {
			token, err := extractToken(request, mw.Cerber)
			if err != nil {
				UnauthorizedJWT(writer, request, err)
				return
			}

			if allowed, err := mw.Authorizator(token, request); !allowed || err != nil {
				UnauthorizedJWT(writer, request, err)
				return
			}

			request.Env["REMOTE_USER"] = token.Claims["id"].(string)
			request.Env["JWT_TOKEN"] = token
		}

		// Execute real action
		handler(writer, request)
	}
}

// Cerber extracts cerber instance from request or fail in panic
func Cerber(request *rest.Request) *api.Cerber {
	c, ok := request.Env["CERBER"].(*api.Cerber)
	if !ok {
		log.Panic("CERBER environment variable has wrong type")
	}
	return c
}

// Token extracts JWT token for the current request
func Token(request *rest.Request) *jwt.Token {
	c, ok := request.Env["JWT_TOKEN"].(*jwt.Token)
	if !ok {
		log.Panic("JWT token has wrong type")
	}

	return c
}

// Extract token from the request and decode payload
// by using provided Cerber instance
func extractToken(request *rest.Request, cbr *api.Cerber) (*jwt.Token, error) {
	authHeader := request.Header.Get("Authorization")

	if authHeader == "" {
		return nil, errors.New("Auth header empty")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return nil, errors.New("Invalid auth header")
	}

	return cbr.ParseToken(parts[1])
}
