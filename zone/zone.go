package zone

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/xphoenix/cerber/config"
)

// Zone repsents a single authorization zone - set of users, groups and permissions along with cryptographic information
// needs token sign
type Zone struct {
	ZName        string `yaml:"name"`
	ZDescription string `yaml:"description,omitempty"`

	ZGroups []Group `yaml:"groups"`
	ZUsers  []User  `yaml:"users"`

	ZSign    SignInfo `yaml:"sign"`
	ZHashing string   `yaml:"hashing"`
}

// Group is a named set of permitted actions. Each action must be in form of
// resource:action, where resource & action are strings
type Group struct {
	Name    string   `yaml:"name"`
	Actions []string `yaml:"actions"`
}

// User tracks information about single user
type User struct {
	Name   string   `yaml:"name"`
	Passwd string   `yaml:"passwd"`
	Groups []string `yaml:"groups,omitempty"`
}

// SignInfo defines signing mechnism along with parameters needed to actually
// sign given token
type SignInfo struct {
	// Certificate used to validate keys signed by the current method
	Method string             `yaml:"method"`
	Cert   config.Certificate `yaml:"cert"`
}

// Name returns current zone name. That value will be used by Cerber
// as Realm name and audience for all users belongs to the zone
func (z *Zone) Name() (name string) {
	return z.ZName
}

// Description returns human redable description of zone. Value is not used
// by Cerber directly
func (z *Zone) Description() (desc string) {
	return z.ZDescription
}

// Certificate provides information enought to sign token issued for the users in
// the current Zone
func (z *Zone) Certificate() (*tls.Certificate, error) {
	if z.ZSign.Method != "RS256" {
		return nil, fmt.Errorf("Zone sign method '%s' doesn't require certificate", z.ZSign.Method)
	}
	return &z.ZSign.Cert.Certificate, nil
}

// HashPassword crypts given password into the zone specific way
func (z *Zone) HashPassword(passwd string) (string, error) {
	h, err := ResolveHashAlgorithm(z.ZHashing)
	if err != nil {
		return "", errors.New("Failed to create password Hasher")
	}
	return h(passwd)
}

// FindUser returns user for the given id or nil if no user found
func (z *Zone) FindUser(userID string) (usr *User, err error) {
	for _, usr := range z.ZUsers {
		if usr.Name == userID {
			return &usr, nil
		}
	}
	return nil, fmt.Errorf("Unknown user: %s", userID)
}

// FindGroup performs lookup of the group by the given name
func (z *Zone) FindGroup(groupID string) (*Group, error) {
	for _, grp := range z.ZGroups {
		if grp.Name == groupID {
			return &grp, nil
		}
	}
	return nil, fmt.Errorf("Unknown group: %s", groupID)
}

// Validate zone configuration. Return nil if configuration is correct or error desription
func (z *Zone) Validate() error {
	return nil
}
