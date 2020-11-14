package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

func isFile(fname string) (os.FileMode, error) {
	stat, err := os.Stat(fname)
	if os.IsNotExist(err) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return stat.Mode(), nil
}

func getServerCertDER(domain, port string) ([]byte, error) {
	certs, err := getServerCertChain(domain, port)
	if err != nil {
		return nil, err
	} else if len(certs) == 0 {
		return nil, errNoCert
	}
	return certs[0].Raw, nil
}

func getServerCertChain(domain, port string) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", domain+":"+port, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates, nil
}
