// seehuhn.de/go/acme/cert - a helper to manage TLS certificates
// Copyright (C) 2020  Jochen Voss <voss@seehuhn.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package cert

import "errors"

var (
	errNoChallenge = errors.New("no http-01 challenge offered")

	errInvalidKey     = errors.New("invalid key")
	errUnknownKeyType = errors.New("unknown key type")
	errUnknownIDType  = errors.New("unknown ID type")
)

// A DomainError indicates a domain relating to a domain.
type DomainError struct {
	Domain, Problem string
	Err             error
}

func (err *DomainError) Error() string {
	msg := err.Domain + ": " + err.Problem
	if err.Err != nil {
		msg += ": " + err.Err.Error()
	}
	return msg
}

func (err *DomainError) Unwrap() error {
	return err.Err
}

// FileError is used to report error conditions relating to files
// or directories.
type FileError struct {
	FileName, Problem string
}

func (err *FileError) Error() string {
	return err.FileName + ": " + err.Problem
}
