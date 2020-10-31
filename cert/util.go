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

func checkDir(dirName string) error {
	stat, err := os.Stat(dirName)
	if os.IsNotExist(err) {
		err = os.MkdirAll(dirName, 0700)
	}
	if err == nil && !stat.IsDir() {
		err = errDirectory
	}
	return err
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
			return nil, errors.New("acme/autocert: unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("acme/autocert: failed to parse private key")
}

func writePEM(fname string, chain [][]byte, Type string, perm os.FileMode) error {
	fd, err := os.OpenFile(fname,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		perm)
	if err != nil {
		return err
	}
	defer fd.Close()

	for _, part := range chain {
		block := &pem.Block{Bytes: part, Type: Type}
		err = pem.Encode(fd, block)
		if err != nil {
			return err
		}
	}
	return nil
}
