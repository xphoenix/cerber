package cerber

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"
	"github.com/xphoenix/cerber/zone"
)

// Cerber is a aunthentification & authoriation server.
//
// It handles diferent mechanisms of authntification, such are Basic, JWT, Facebook
// e.t.c. Once logedin Cerber generates JWT token that could be used for authorization
// in different actions
type Cerber struct {
	Realm     string
	providers []zone.Provider
}

// New creates a new instance of cerber checking that passed parameters are all makes sense
//
// realm is auth realm url redable name
// alg crypto algorhim used to sign token, see Cerber.SigningAlgorithm for possible values
// key string used as a key to sign tokens
// timeout fraction of time during what token is considered as valid. If not set default value of 15m is used
// refresh maxmum time during what token is allowed to be refreshed. If not set default value if 1h is used
func New(realm string) (instance *Cerber, err error) {
	return &Cerber{
		Realm:     realm,
		providers: make([]zone.Provider, 0, 3),
	}, nil
}

// AddProvider Registers new Cerber Zone Provider which will be used to lookup Authentification
// zones
func (c *Cerber) AddProvider(p zone.Provider) {
	for _, ep := range c.providers {
		if ep == p {
			return
		}
	}

	c.providers = append(c.providers, p)
}

// FindZone looks up zone with given name across all provider registered in the Cerber instance. If there is no
// provider with Zone has given name error returns
func (c *Cerber) FindZone(name string) (zone.Zone, error) {
	for _, p := range c.providers {
		z, err := p.FindZone(name)
		if err != nil {
			// TODO: Log only errors, do not log 'not found'
			log.Warnf("Error query provider %s[%s]: %s\n", p.URL().String(), name, err)
		}

		if z != nil {
			return z, nil
		}
	}
	return nil, fmt.Errorf("There is no zone with name: %s", name)
}

// Authorize given user in the given zone
// Provided password must be encrypted by zone specific method
func (c *Cerber) Authorize(z zone.Zone, user, passwd string) ([]string, error) {
	// TODO: check password, calculate & resolve actions
	usr, err := z.FindUser(user)
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain user info: %s", err)
	}

	if usr.Passwd != passwd {
		return nil, errors.New("Wrong password")
	}

	// Resolve user groups
	actions := make([]string, 0, 3)
	for _, g := range usr.Groups {
		grp, err := z.FindGroup(g)
		if err != nil {
			return nil, fmt.Errorf("Failed to get group info: %s", g)
		}
		actions = append(actions, grp.Actions...)
	}

	return actions, nil
}

// GenerateToken creates new token for the given user
func (c *Cerber) GenerateToken(service, userName, account, scope string, claims map[string]interface{}) (t *string, err error) {
	// Get zone instance resposible for handling requested service
	z, err := c.FindZone(service)
	if err != nil {
		return nil, fmt.Errorf("Unknown zone: %s", service)
	}

	// Create token
	cert, err := z.Certificate()
	if err != nil {
		return nil, fmt.Errorf("Failed to get certificate for the zone '%s': %s", service, err)
	}

	// Copy claims first, later stages will override system claims with neccessary values
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	for k, v := range claims {
		token.Claims[k] = v
	}

	// Copy certificates will be used to validate signature
	// TODO: support other signing methods
	size := len(cert.Certificate)
	array := make([]string, size, size)
	for i, cert := range cert.Certificate {
		array[i] = base64.StdEncoding.EncodeToString(cert)
	}
	token.Header["x5c"] = array

	// Set Cerber specific claims
	// TODO: move time related configs into zone
	duration, _ := time.ParseDuration("15m")
	token.Claims["id"] = userName
	token.Claims["exp"] = time.Now().Add(duration).Unix()
	token.Claims["orig_iat"] = time.Now().Unix()

	//Sign token
	tokenString, err := token.SignedString(cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &tokenString, nil
}

// ParseToken parse given token string and return instance of jwt.Token
func (c *Cerber) ParseToken(tkn string) (*jwt.Token, error) {
	// return jwt.Parse(tkn, func(token *jwt.Token) (interface{}, error) {
	// 	return c.Key, nil
	// })
	return nil, errors.New("Not implemented yet")
}
