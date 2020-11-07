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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
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
	err := createDirIfNeeded(config.AccountDir, 0700)
	if err != nil {
		return nil, err
	}

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

// Domains returns all domain names known to this manager.
func (m *Manager) Domains() []string {
	dd := make([]string, len(m.config.Sites))
	for i, site := range m.config.Sites {
		dd[i] = site.Domain
	}
	return dd
}

// CheckConfig checks the configuration file of `m` for problems.
func (m *Manager) CheckConfig() error {
	_, err := m.getAccountKey()
	if err != nil {
		return err
	}

	if len(m.config.Sites) == 0 {
		return &FileError{
			Problem: "contains no sites",
		}
	}

	// try to publish a file for each site
	seen := make(map[string]bool)
	for _, site := range m.config.Sites {
		domain := site.Domain
		if seen[domain] {
			return &FileError{
				Problem: "duplicate domain",
			}
		}
		seen[domain] = true

		_, err := m.getKey(domain)
		if err != nil {
			return err
		}

		err = m.TestChallenge(domain)
		if err != nil {
			return err
		}
	}

	return nil
}

// TestChallenge tries to publish and read back a challenge response file for
// the given domain.
func (m *Manager) TestChallenge(domain string) error {
	token := make([]byte, 8)
	_, err := io.ReadFull(rand.Reader, token)
	if err != nil {
		return err
	}
	tokenStr := base64.RawURLEncoding.EncodeToString(token)
	urlPath := path.Join(".well-known/acme-challenge", "jvcert-"+tokenStr)
	fname, err := m.publishFile(domain, urlPath, token)
	if err != nil {
		return &DomainError{
			Domain:  domain,
			Problem: "cannot publish file",
			Err:     err,
		}
	}
	defer os.Remove(fname)

	resp, err := http.Get("http://" + domain + "/" + urlPath)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil || resp.StatusCode != 200 {
		if err == nil {
			err = errors.New(resp.Status)
		}
		return &DomainError{
			Domain:  domain,
			Problem: "cannot get challenge response via http",
			Err:     err,
		}
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return &DomainError{
			Domain:  domain,
			Problem: "cannot read challenge response body",
			Err:     err,
		}
	}

	if bytes.Compare(token, body) != 0 {
		return &DomainError{
			Domain:  domain,
			Problem: "challenge response body corrupted",
		}
	}

	return nil
}

// Info contains information about a single certificate installed on the
// system.
type Info struct {
	Domain    string
	IsValid   bool
	IsMissing bool
	Expiry    time.Time
	Message   string
}

// GetCertInfo returns information about a certificate managed by m.
func (m *Manager) GetCertInfo(domains []string) (*Info, error) {
	certFileName, err := m.config.GetCertFileName(domains[0])
	if err != nil {
		return nil, err
	}
	chainDER, err := loadCertChain(certFileName)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	info, err := m.checkCert(time.Now(), chainDER, domains)
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
	for _, domain := range domains {
		err := m.TestChallenge(domain)
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
	info, err := m.checkCert(time.Now(), chainDER, domains)
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

func (m *Manager) getWebRoot(domain string) (string, error) {
	return m.config.GetWebRoot(domain)
}

// Put a file with the given contents on the web server.
// Returns the created file name (to be used when later removing the file)
// and an error, if any.
func (m *Manager) publishFile(domain, path string, contents []byte) (string, error) {
	root, err := m.getWebRoot(domain)
	if err != nil {
		return "", err
	}
	fname := filepath.Join(root, filepath.Clean(filepath.FromSlash(path)))

	err = os.MkdirAll(filepath.Dir(fname), 0755)
	if err != nil {
		return "", err
	}

	fd, err := os.Create(fname)
	if err != nil {
		return "", err
	}
	defer fd.Close()

	_, err = fd.Write(contents)
	return fname, err
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

func (m *Manager) checkCert(now time.Time, chainDER [][]byte, domains []string) (*Info, error) {
	info := &Info{
		Domain: domains[0],
	}

	if len(chainDER) == 0 {
		info.IsMissing = true
		info.Message = "missing"
		return info, nil
	}

	siteCertDER := chainDER[0]
	siteCert, err := x509.ParseCertificate(siteCertDER)
	if err != nil {
		return nil, err
	}
	if now.Before(siteCert.NotBefore) {
		info.Message = "not valid until " + siteCert.NotBefore.String()
		return info, nil
	}
	info.Expiry = siteCert.NotAfter
	if now.After(siteCert.NotAfter) {
		info.Message = "expired on " + siteCert.NotAfter.String()
		return info, nil
	}

	// Ensure the siteCert corresponds to the correct private key.
	key, err := m.getKey(domains[0])
	if err != nil {
		return nil, err
	}
	switch pub := siteCert.PublicKey.(type) {
	case *rsa.PublicKey:
		prv, ok := key.(*rsa.PrivateKey)
		if !ok || pub.N.Cmp(prv.N) != 0 {
			info.Expiry = time.Time{}
			info.Message = "public key doesn't match private key"
			return info, nil
		}
	case *ecdsa.PublicKey:
		prv, ok := key.(*ecdsa.PrivateKey)
		if !ok || pub.X.Cmp(prv.X) != 0 || pub.Y.Cmp(prv.Y) != 0 {
			info.Expiry = time.Time{}
			info.Message = "public key doesn't match private key"
			return info, nil
		}
	default:
		return nil, errUnknownKeyType
	}

	intermediates := x509.NewCertPool()
	for _, caCertDER := range chainDER[1:] {
		caCert, err := x509.ParseCertificate(caCertDER)
		if err != nil {
			return nil, err
		}
		intermediates.AddCert(caCert)
	}
	for _, domain := range domains {
		opts := x509.VerifyOptions{
			DNSName:       domain,
			Roots:         m.roots,
			Intermediates: intermediates,
			CurrentTime:   now,
		}
		_, err = siteCert.Verify(opts)
		if err != nil {
			info.Message = err.Error()
			return info, nil
		}
	}

	info.IsValid = true
	info.Message = "issued by " + siteCert.Issuer.String()

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

	fname, err := m.publishFile(domain, path, []byte(contents))
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
