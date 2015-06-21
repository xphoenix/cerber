package rest

import (
	"fmt"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/ant0ine/go-json-rest/rest"
)

// Random to generate UUID
var Random *os.File

func init() {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		log.Fatal(err)
	}
	Random = f
}

// LogMiddleware produces the access log written into structured form. Along with that it provides request specific
// logger instance. Normal work depends on TimerMiddleware and RecorderMiddleware that must be in the wrapped middlewares. It
// also uses request.Env["REMOTE_USER"].(string) set by the auth middlewares.
type LogMiddleware struct {

	// Logger points to the logger object used by this middleware, it defaults to
	// log.New().
	Logger *log.Logger

	out *log.Entry
}

// MiddlewareFunc makes LogMiddleware implement the Middleware interface.
func (mw *LogMiddleware) MiddlewareFunc(h rest.HandlerFunc) rest.HandlerFunc {

	// set the default Logger
	if mw.Logger == nil {
		mw.Logger = log.New()
	}

	return func(w rest.ResponseWriter, r *rest.Request) {
		// Setup global logger instance
		mw.out = mw.Logger.WithFields(log.Fields{
			"request": generateRequestID(),
		})
		r.Env["LOGGER"] = mw.out

		// call the handler
		h(w, r)

		fields := makeAccessLogRecord(r)
		mw.out.WithFields(fields).Info("request served")
	}
}

// Logger extracts logger from the request context. If logger is not set, function panic
func Logger(request *rest.Request) *log.Entry {
	l, ok := request.Env["LOGGER"].(*log.Entry)
	if !ok {
		log.Panic("LOGGER environment variable has wrong type")
	}
	return l
}

func generateRequestID() string {
	b := make([]byte, 16)
	Random.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func makeAccessLogRecord(r *rest.Request) log.Fields {

	var timestamp *time.Time
	if r.Env["START_TIME"] != nil {
		timestamp = r.Env["START_TIME"].(*time.Time)
	}

	var statusCode int
	if r.Env["STATUS_CODE"] != nil {
		statusCode = r.Env["STATUS_CODE"].(int)
	}

	var responseTime *time.Duration
	if r.Env["ELAPSED_TIME"] != nil {
		responseTime = r.Env["ELAPSED_TIME"].(*time.Duration)
	}

	var remoteUser string
	if r.Env["REMOTE_USER"] != nil {
		remoteUser = r.Env["REMOTE_USER"].(string)
	}

	return log.Fields{
		"Timestamp":    timestamp,
		"StatusCode":   statusCode,
		"ResponseTime": responseTime,
		"HttpMethod":   r.Method,
		"RequestURI":   r.URL.RequestURI(),
		"RemoteUser":   remoteUser,
		"UserAgent":    r.UserAgent(),
	}
}
