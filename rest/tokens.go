package rest

import "github.com/ant0ine/go-json-rest/rest"

// RefreshToken is a rest handler function that accepts token provided by
// middleware and generates new token which is full copy of original token
// but extended in time
func RefreshToken(writer rest.ResponseWriter, request *rest.Request) {
	tkn, cerber := Token(request), Cerber(request)
	if tkn == nil {
		UnauthorizedJWT(writer, request, nil)
		return
	}

	newToken, err := cerber.RefreshToken(tkn)
	if err != nil {
		UnauthorizedJWT(writer, request, err)
		return
	}

	writer.WriteJson(loginResponse{newToken})
}

// ValidateToken is a rest handler function that return details of the token
// provided by middleware. If response of that handler is 200 then given token
// is valid
func ValidateToken(writer rest.ResponseWriter, request *rest.Request) {
	tkn := Token(request)
	if tkn == nil {
		UnauthorizedJWT(writer, request, nil)
	}

	writer.WriteJson(tkn.Claims)
}
