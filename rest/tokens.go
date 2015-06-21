package rest

import "github.com/ant0ine/go-json-rest/rest"

// RefreshToken is a rest handler function that accepts token provided by
// middleware and generates new token which is full copy of original token
// but extended in time
func RefreshToken(writer rest.ResponseWriter, request *rest.Request) {

}

// ValidateToken is a rest handler function that return details of the token
// provided by middleware. If response of that handler is 200 then given token
// is valid
func ValidateToken(writer rest.ResponseWriter, request *rest.Request) {

}
