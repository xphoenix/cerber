package zone

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Hasher builds hash of the given string and return hex representation of result bytes
type Hasher func(string) (string, error)

//ResolveHashAlgorithm returns hashing function based on the algorithm name
func ResolveHashAlgorithm(name string) (Hasher, error) {
	switch strings.ToUpper(name) {
	case "NONE":
		return none, nil
	case "MD5":
		return md5Hasher, nil
	}
	return nil, fmt.Errorf("Unknown hashing algorithm: %s", name)
}

// return password as it is - no hashing
func none(passwd string) (string, error) {
	return passwd, nil
}

// convert string into md5 representation
func md5Hasher(passwd string) (string, error) {
	h := md5.New()
	io.WriteString(h, passwd)

	data := h.Sum(nil)
	return hex.EncodeToString(data), nil
}
