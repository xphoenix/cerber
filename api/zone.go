package api

import (
	"crypto/tls"
	"time"
)

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

// Zone repsents a single authorization zone - set of users, groups and permissions along with cryptographic information
// needs token sign
type Zone interface {
	// Name returns current zone name. That value will be used by Cerber
	// as Realm name and audience for all users belongs to the zone
	Name() (name string)

	// Description returns human redable description of zone. Value is not used
	// by Cerber directly
	Description() (desc string)

	// Timeout returns duration while token in that zone considered as valid. During that time token could be refreshed
	// and prolong itself life time
	Timeout() time.Duration

	// Maximum life time for a token. Eac token could be refreshed non limited number of time, but total life time
	// can't be more then MaxRefresh duration. If configured value is 0 then no MaxRefresh limit applied
	MaxRefresh() time.Duration

	// Certificate provides information enought to sign token issued for the users in
	// the current Zone
	Certificate() (*tls.Certificate, error)

	// HashPassword crypts given password into the zone specific way
	HashPassword(passwd string) (string, error)

	// FindUser returns user for the given id or nil if no user found
	FindUser(userID string) (usr *User, err error)

	// FindGroup performs lookup of the group by the given name
	FindGroup(groupID string) (*Group, error)
}
