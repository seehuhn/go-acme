package cert

import "errors"

var (
	errInvalidKey         = errors.New("invalid key")
	errDirectory          = errors.New("not a directory")
	errInvalidCertificate = errors.New("invalid certificate")
	errNoChallenge        = errors.New("no http-01 challenge offered")
)
