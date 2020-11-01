// seehuhn.de/go/letsencrypt/cert - a helper to manage TLS certificates
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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/acme"
)

// Manager holds all state required to generate and/or renew certificates
// via Let's Encrypt.
type Manager struct {
	directory string
	config    *Config
	roots     *x509.CertPool

	accountKey crypto.Signer
	siteKeys   map[int]crypto.Signer

	webPathTmpl *template.Template
}

// NewManager creates a new certificate manager.
func NewManager(config *Config, debug bool) (*Manager, error) {
	err := createDirIfNeeded(config.AccountDir, 0700)
	if err != nil {
		return nil, err
	}

	keyName := filepath.Join(config.AccountDir, "account.key")
	accountKey, err := loadOrCreatePrivateKey(keyName)
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
		directory:  directory,
		config:     config,
		roots:      roots,
		accountKey: accountKey,
		siteKeys:   make(map[int]crypto.Signer),
	}, nil
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

// GetCertInfo returns information about all certificates managed by `m`.
func (m *Manager) GetCertInfo() ([]*Info, error) {
	n := len(m.config.Sites)
	res := make([]*Info, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		certFileName, err := m.config.GetCertFileName(i)
		if err != nil {
			return nil, err
		}
		chainDER, err := loadCertChain(certFileName)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}

		info, err := m.checkCert(now, chainDER, i)
		if err != nil {
			return nil, err
		}
		res[i] = info
	}
	return res, nil
}

func (m *Manager) checkCert(now time.Time, chainDER [][]byte, i int) (*Info, error) {
	domain := m.config.Sites[i].Domain
	info := &Info{
		Domain: domain,
	}

	if chainDER == nil {
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
	key, err := m.getKey(i)
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

	info.IsValid = true
	info.Message = "issued by " + siteCert.Issuer.String()

	return info, nil
}

// InstallDummyCert installs a self-signed dummy certificate for
// site number `i`.
func (m *Manager) InstallDummyCert(i int, expiry time.Duration) error {
	now := time.Now()
	domain := m.config.Sites[i].Domain
	fname, err := m.config.GetCertFileName(i)
	privKey, err := m.getKey(i)
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
	return writePEM(fname, [][]byte{caCertDER}, "CERTIFICATE", 0644)
}

func (m *Manager) getKey(i int) (crypto.Signer, error) {
	if key, ok := m.siteKeys[i]; ok {
		return key, nil
	}

	keyPath, err := m.config.GetKeyFileName(i)
	if err != nil {
		return nil, err
	}

	key, err := loadOrCreatePrivateKey(keyPath)
	if err != nil {
		return nil, err
	}

	m.siteKeys[i] = key
	return key, nil
}

// verifyAccount loads or creates the private key for the account and registers
// the account with Let's Encrypt if needed. The function sets the m.client
// field.
func (m *Manager) verifyAccount(ctx context.Context) (*acme.Client, error) {
	client := &acme.Client{
		DirectoryURL: m.directory,
		UserAgent:    packageVersion,
		Key:          m.accountKey,
	}
	acct := &acme.Account{
		Contact: []string{"mailto:" + m.config.ContactEmail},
	}
	_, err := client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil && err != acme.ErrAccountAlreadyExists {
		return nil, err
	}
	return client, nil
}

// RenewCertificate requests and installs a new certificate for the given site.
func (m *Manager) RenewCertificate(i int) error {
	ctx := context.TODO()

	// this sets m.client
	client, err := m.verifyAccount(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	site := m.config.Sites[i]
	domain := site.Domain
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return err
	}
	order, err = m.finishAuthorization(ctx, client, order, site)
	if err != nil {
		return err
	}

	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: site.Domain},
		DNSNames: []string{},
		// ExtraExtensions: ext,
	}
	key, err := m.getKey(i)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return err
	}
	chainDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return err
	}
	info, err := m.checkCert(now, chainDER, i)
	if err != nil {
		return err
	}
	if !info.IsValid {
		return errors.New("received invalid certificate: " + info.Message)
	}

	certPath, err := m.config.GetCertFileName(i)
	if err != nil {
		return err
	}
	fmt.Println("writing", certPath)
	err = writePEM(certPath, chainDER, "CERTIFICATE", 0644)
	if err != nil {
		return err
	}
	return nil
}

func (m *Manager) finishAuthorization(ctx context.Context, client *acme.Client,
	order *acme.Order, site *ConfigSite) (*acme.Order, error) {
	if order.Status == acme.StatusReady {
		// fmt.Println(site.Domain, "already authorized")
		return order, nil
	}
	// fmt.Println(site.Domain, "needs authorization")
	for _, zurl := range order.AuthzURLs {
		z, err := client.GetAuthorization(ctx, zurl)
		if err != nil {
			return nil, err
		}
		if z.Status != acme.StatusPending {
			continue
		}

		var challenge *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "http-01" {
				challenge = c
				break
			}
		}
		if challenge == nil {
			return nil, errNoChallenge
		}

		resp, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return nil, err
		}

		webPath := site.WebPath
		if webPath == "" {
			if m.webPathTmpl == nil {
				m.webPathTmpl = template.New("webPath")
				m.webPathTmpl = template.Must(m.webPathTmpl.Parse(m.config.DefaultWebPath))
			}

			buf := &strings.Builder{}
			err := m.webPathTmpl.Execute(buf, map[string]interface{}{
				"Config": m.config,
				"Site":   site,
			})
			if err != nil {
				return nil, err
			}
			webPath = buf.String()
		}
		webPath = webPath + client.HTTP01ChallengePath(challenge.Token)
		os.MkdirAll(filepath.Dir(webPath), 0755)
		ioutil.WriteFile(webPath, []byte(resp), 0644)

		_, err = client.Accept(ctx, challenge)
		if err != nil {
			return nil, err
		}

		_, err = client.WaitAuthorization(ctx, z.URI)
		if err != nil {
			return nil, err
		}
	}
	fmt.Println("success")
	return client.WaitOrder(ctx, order.URI)
}
