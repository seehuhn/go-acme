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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"golang.org/x/crypto/acme"
)

const accountKeyName = "account.key"

// Manager holds all state required to generate and/or renew certificates
// via Let's Encrypt.
type Manager struct {
	directory string
	config    *Config
	roots     *x509.CertPool

	accountKey crypto.Signer
	siteKeys   map[string]crypto.Signer

	webPathTmpl *template.Template
}

// NewManager creates a new certificate manager.
func NewManager(config *Config, debug bool) (*Manager, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	directory := defaultACMEDirectory
	if debug {
		directory = debugACMEDirectory
		roots.AppendCertsFromPEM([]byte(fakeRootCert))
	}

	return &Manager{
		directory: directory,
		config:    config,
		roots:     roots,

		siteKeys: make(map[string]crypto.Signer),
	}, nil
}

// Info contains information about a single certificate installed on the
// system.
type Info struct {
	Cert      *x509.Certificate
	IsValid   bool
	IsMissing bool
	Expiry    time.Time
	Message   string
}

// GetCertInfo returns information about a certificate managed by m.
func (m *Manager) GetCertInfo(domain string) (*Info, error) {
	certFileName, err := m.config.GetCertFileName(domain)
	if err != nil {
		return nil, err
	}
	chainDER, err := loadCertChain(certFileName)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	info, err := m.checkCertDER(time.Now(), chainDER, domain)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// InstallSelfSigned installs a self-signed dummy certificate for a domain.
func (m *Manager) InstallSelfSigned(domain string, expiry time.Duration) error {
	now := time.Now()

	privKey, err := m.getKey(domain)
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: domain},
		SerialNumber: newSerialNum(),
		NotBefore:    now,
		NotAfter:     now.Add(expiry),
		DNSNames:     []string{domain},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl,
		privKey.Public(), privKey)
	if err != nil {
		return err
	}
	chainDER := [][]byte{caCertDER}

	certPath, err := m.config.GetCertFileName(domain)
	if err != nil {
		return err
	}
	return writePEM(certPath, chainDER, "CERTIFICATE", 0644)
}

// RenewCertificate requests and installs a new certificate for the given
// set of domains.
func (m *Manager) RenewCertificate(domains []string) error {
	// Make sure we can respond to challenges before using any
	// of our allowance with the ACME provider.
	for _, domain := range domains {
		err := m.config.TestChallenge(domain)
		if err != nil {
			return err
		}
	}

	csr, err := m.getCSR(domains)
	if err != nil {
		return err
	}

	ctx := context.TODO()

	client, err := m.getClient(ctx)
	if err != nil {
		return err
	}
	order, err := m.getOrder(ctx, client, domains)
	if err != nil {
		return err
	}
	chainDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return err
	}
	info, err := m.checkCertDER(time.Now(), chainDER, domains[0])
	if err != nil {
		return err
	}
	if !info.IsValid {
		return errors.New("received invalid certificate: " + info.Message)
	}

	certPath, err := m.config.GetCertFileName(domains[0])
	if err != nil {
		return err
	}
	return writePEM(certPath, chainDER, "CERTIFICATE", 0644)
}

func (m *Manager) getKey(domain string) (crypto.Signer, error) {
	if key, ok := m.siteKeys[domain]; ok {
		return key, nil
	}

	keyPath, err := m.config.GetKeyFileName(domain)
	if err != nil {
		return nil, err
	}

	key, err := loadOrCreatePrivateKey(keyPath)
	if err != nil {
		return nil, err
	}

	m.siteKeys[domain] = key
	return key, nil
}

func (m *Manager) getCSR(domains []string) ([]byte, error) {
	key, err := m.getKey(domains[0])
	if err != nil {
		return nil, err
	}

	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
		// ExtraExtensions: ext,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

func (m *Manager) getAccountKey() (crypto.Signer, error) {
	if m.accountKey != nil {
		return m.accountKey, nil
	}

	keyName := filepath.Join(m.config.AccountDir, accountKeyName)
	accountKey, err := loadOrCreatePrivateKey(keyName)
	if err != nil {
		return nil, err
	}
	m.accountKey = accountKey
	return accountKey, nil
}

func (m *Manager) checkCertDER(now time.Time, chainDER [][]byte, domain string) (*Info, error) {
	chain := make([]*x509.Certificate, len(chainDER))
	for i, der := range chainDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain[i] = cert
	}

	info, err := m.CheckCert(now, chain, domain)
	if err != nil {
		return nil, err
	}

	if info.IsValid {
		key, err := m.getKey(domain)
		if err != nil {
			return nil, err
		}
		err = checkCertMatchesKey(info.Cert, key)
		if err != nil {
			info.IsValid = false
			info.Message = err.Error()
		}
	}

	return info, nil
}

// Ensure the siteCert corresponds to the correct private key.
func checkCertMatchesKey(cert *x509.Certificate, key crypto.Signer) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		prv, ok := key.(*rsa.PrivateKey)
		if !ok || pub.N.Cmp(prv.N) != 0 {
			return errWrongKey
		}
	case *ecdsa.PublicKey:
		prv, ok := key.(*ecdsa.PrivateKey)
		if !ok || pub.X.Cmp(prv.X) != 0 || pub.Y.Cmp(prv.Y) != 0 {
			return errWrongKey
		}
	default:
		return errWrongKey // unknown key type
	}
	return nil
}

func (m *Manager) CheckCert(now time.Time, chain []*x509.Certificate, domain string) (*Info, error) {
	info := &Info{}

	if len(chain) == 0 {
		info.IsMissing = true
		info.Message = "missing"
		return info, nil
	}

	siteCert := chain[0]
	info.Cert = siteCert
	info.Expiry = siteCert.NotAfter

	intermediates := x509.NewCertPool()
	for _, caCert := range chain[1:] {
		intermediates.AddCert(caCert)
	}
	opts := x509.VerifyOptions{
		DNSName:       domain,
		Roots:         m.roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	}
	_, err := siteCert.Verify(opts)
	if err != nil {
		info.Message = err.Error()
		return info, nil
	}

	info.IsValid = true

	return info, nil
}

func (m *Manager) getClient(ctx context.Context) (*acme.Client, error) {
	accountKey, err := m.getAccountKey()
	if err != nil {
		return nil, err
	}

	client := &acme.Client{
		DirectoryURL: m.directory,
		UserAgent:    PackageVersion,
		Key:          accountKey,
	}
	acct := &acme.Account{}
	if m.config.ContactEmail != "" {
		acct.Contact = []string{"mailto:" + m.config.ContactEmail}
	}
	_, err = client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil && err != acme.ErrAccountAlreadyExists {
		return nil, err
	}
	return client, nil
}

func (m *Manager) getOrder(ctx context.Context, client *acme.Client,
	domains []string) (*acme.Order, error) {
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return nil, err
	}
	if order.Status == acme.StatusReady {
		return order, nil
	}

	for _, authzURL := range order.AuthzURLs {
		err := m.authorizeOne(ctx, client, authzURL)
		if err != nil {
			return nil, err
		}
	}
	return client.WaitOrder(ctx, order.URI)
}

func (m *Manager) authorizeOne(ctx context.Context, client *acme.Client, authzURL string) error {
	auth, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return err
	}
	if auth.Identifier.Type != "dns" {
		return errUnknownIDType
	}
	if auth.Status != acme.StatusPending {
		return nil
	}

	var challenge *acme.Challenge
	for _, c := range auth.Challenges {
		if c.Type == "http-01" {
			challenge = c
			break
		}
	}
	if challenge == nil {
		return errNoChallenge
	}

	domain := auth.Identifier.Value
	path := client.HTTP01ChallengePath(challenge.Token)
	contents, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return err
	}

	fname, err := m.config.PublishFile(domain, path, []byte(contents))
	if fname != "" {
		defer os.Remove(fname)
	}
	if err != nil {
		return err
	}

	_, err = client.Accept(ctx, challenge)
	if err != nil {
		return err
	}

	_, err = client.WaitAuthorization(ctx, auth.URI)
	return err
}
