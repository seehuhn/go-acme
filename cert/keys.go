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

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"
)

// loadOrCreatePrivateKey loads the account key from disk, or generates
// a new key if no existing key is found.
func loadOrCreatePrivateKey(fname string) (crypto.Signer, error) {
	key, err := loadPrivateKey(fname)
	if os.IsNotExist(err) {
		var ecKey *ecdsa.PrivateKey
		ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			key = ecKey
			privDER, err := x509.MarshalECPrivateKey(ecKey)
			if err != nil {
				return nil, err
			}
			err = writePEM(fname, [][]byte{privDER}, "EC PRIVATE KEY", 0600)
			if err != nil {
				return nil, err
			}
		}
	}
	return key, err
}

func loadPrivateKey(fname string) (crypto.Signer, error) {
	// TODO(voss): return an error if the key is world-readable
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	priv, _ := pem.Decode(data)
	if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
		return nil, errInvalidKey
	}
	return parsePrivateKey(priv.Bytes)
}

// getDERCert loads the site certificate in DER format.  If no certificate
// is found, generate a short-lived, self-signed certificate instead.
func getDERCert(fname, domain string, privKey crypto.Signer) ([]byte, error) {
	caCertDER, err := loadCert(fname)
	if !os.IsNotExist(err) {
		return caCertDER, err
	}

	// Generate a self-signed certificate
	tmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: domain},
		SerialNumber: newSerialNum(),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		// DNSNames:     []string{domain},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	caCertDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		privKey.Public(), privKey)
	if err != nil {
		return nil, err
	}
	err = writePEM(fname, [][]byte{caCertDER}, "CERTIFICATE", 0644)
	if err != nil {
		return nil, err
	}
	return caCertDER, nil
}

func loadCert(fname string) ([]byte, error) {
	chain, err := loadCertChain(fname)
	if err != nil {
		return nil, err
	}
	return chain[0], nil
}

func loadCertChain(fname string) ([][]byte, error) {
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	errInvalid := &FileError{
		FileName: fname,
		Problem:  "not a certificate in PEM encoding",
	}

	var chain [][]byte
	for len(data) > 0 {
		var certDER *pem.Block
		certDER, data = pem.Decode(data)
		if certDER == nil || !strings.Contains(certDER.Type, "CERTIFICATE") {
			return nil, errInvalid
		}
		chain = append(chain, certDER.Bytes)
	}
	if len(chain) == 0 {
		return nil, errInvalid
	}
	return chain, nil
}

var maxSerial *big.Int

func newSerialNum() *big.Int {
	if maxSerial == nil {
		maxSerial = big.NewInt(2)
		maxSerial.Exp(maxSerial, big.NewInt(8*16), nil)
	}
	x, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		panic(err)
	}
	return x
}
