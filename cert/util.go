// seehuhn.de/go/acme/cert - renew and manage server certificates
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

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func isDir(dirName string) (bool, error) {
	stat, err := os.Stat(dirName)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return stat.IsDir(), nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
//
// Inspired by parsePrivateKey in crypto/tls/tls.go.
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("acme/cert: unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("acme/autoc: failed to parse private key")
}

func writePEM(fname string, dataDER [][]byte, Type string, perm os.FileMode) error {
	fd, err := os.OpenFile(fname,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		perm)
	if err != nil {
		return err
	}
	defer fd.Close()

	for _, part := range dataDER {
		block := &pem.Block{Bytes: part, Type: Type}
		err = pem.Encode(fd, block)
		if err != nil {
			return err
		}
	}
	return nil
}

func stringSliceLess(a, b []string) bool {
	for n := 0; ; n++ {
		if len(b) <= n {
			return false
		} else if len(a) <= n {
			return true
		}
		if a[n] < b[n] {
			return true
		} else if a[n] > b[n] {
			return false
		}
	}
}
