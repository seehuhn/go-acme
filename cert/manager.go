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
	config        *Config
	client        *acme.Client
	needsRenewing []int
	siteKeys      map[int]crypto.Signer

	webPathTmpl  *template.Template
	certPathTmpl *template.Template
}

// NewManager creates a new certificate manager.  This sets up a
// new account with Let's Encrypt, if no previous account is found.
func NewManager(ctx context.Context, config *Config) (*Manager, error) {
	m := &Manager{
		config:   config,
		siteKeys: make(map[int]crypto.Signer),
	}

	needsRenewing, err := m.verifySites()
	if err != nil || len(needsRenewing) == 0 {
		return nil, err
	}
	m.needsRenewing = needsRenewing

	// this sets m.client
	err = m.verifyAccount(ctx)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// verifyAccount loads or creates the private key for the account and registers
// the account with Let's Encrypt if needed. The function sets the m.client
// field.
func (m *Manager) verifyAccount(ctx context.Context) error {
	err := checkDir(m.config.AccountDir)
	if err != nil {
		return err
	}

	keyName := filepath.Join(m.config.AccountDir, "account.pem")
	accountKey, err := getPrivateKey(keyName)
	if err != nil {
		return err
	}
	m.client = &acme.Client{
		DirectoryURL: m.config.ACMEDirectory,
		UserAgent:    packageVersion,
		Key:          accountKey,
	}
	acct := &acme.Account{
		Contact: []string{"mailto:" + m.config.ContactEmail},
	}
	_, err = m.client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil && err != acme.ErrAccountAlreadyExists {
		return err
	}
	return nil
}

// verifySites sets up the key directories for all sites and returns
// a list of sites which need new certificates.
//
// This function also fills in m.siteKeys .
func (m *Manager) verifySites() ([]int, error) {
	keyPathTmpl := template.New("keyPath")
	keyPathTmpl = template.Must(keyPathTmpl.Parse(m.config.DefaultSiteKey))
	certPathTmpl := template.New("certPath")
	certPathTmpl = template.Must(certPathTmpl.Parse(m.config.DefaultSiteCert))

	now := time.Now()
	deadline := now.Add(7 * 24 * time.Hour)
	var needsRenewing []int
	for i, site := range m.config.Sites {
		keyPath := site.KeyPath
		if keyPath == "" {
			buf := &strings.Builder{}
			err := keyPathTmpl.Execute(buf, map[string]interface{}{
				"Config": m.config,
				"Site":   site,
			})
			if err != nil {
				return nil, err
			}
			keyPath = buf.String()
		}

		key, err := getPrivateKey(keyPath)
		if err != nil {
			return nil, err
		}

		certPath := site.CertPath
		if certPath == "" {
			buf := &strings.Builder{}
			err := certPathTmpl.Execute(buf, map[string]interface{}{
				"Config": m.config,
				"Site":   site,
			})
			if err != nil {
				return nil, err
			}
			certPath = buf.String()
		}

		cert, err := getDERCert(certPath, site.Domain, key)
		if err != nil {
			return nil, err
		}
		cl, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}

		if cl.NotBefore.After(now) || cl.NotAfter.Before(deadline) {
			needsRenewing = append(needsRenewing, i)
			m.siteKeys[i] = key
		}
	}
	return needsRenewing, nil
}

// RenewAll renews all certificates
func (m *Manager) RenewAll(ctx context.Context) error {
	client := m.client
	now := time.Now()
	for _, i := range m.needsRenewing {
		site := m.config.Sites[i]
		domain := site.Domain
		order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
		if err != nil {
			return err
		}
		order, err = m.finishAuthorization(ctx, order, site)
		if err != nil {
			return err
		}

		req := &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: site.Domain},
			DNSNames: []string{},
			// ExtraExtensions: ext,
		}
		key := m.siteKeys[i]
		csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
		if err != nil {
			return err
		}
		chainDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
		if err != nil {
			return err
		}
		err = validateCert(chainDER, site.Domain, key, now)
		if err != nil {
			return err
		}

		certPath := site.CertPath
		if certPath == "" {
			if m.certPathTmpl == nil {
				m.certPathTmpl = template.New("certPath")
				m.certPathTmpl = template.Must(m.certPathTmpl.Parse(m.config.DefaultSiteCert))
			}

			buf := &strings.Builder{}
			err := m.certPathTmpl.Execute(buf, map[string]interface{}{
				"Config": m.config,
				"Site":   site,
			})
			if err != nil {
				return err
			}
			certPath = buf.String()
		}
		fmt.Println("writing", certPath)
		err = writePEM(certPath, chainDER, "CERTIFICATE", 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) finishAuthorization(ctx context.Context, order *acme.Order, site *SiteConfig) (*acme.Order, error) {
	if order.Status == acme.StatusReady {
		fmt.Println(site.Domain, "already authorized")
		return order, nil
	}
	fmt.Println(site.Domain, "needs authorization")
	for _, zurl := range order.AuthzURLs {
		z, err := m.client.GetAuthorization(ctx, zurl)
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

		resp, err := m.client.HTTP01ChallengeResponse(challenge.Token)
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
		webPath = webPath + m.client.HTTP01ChallengePath(challenge.Token)
		os.MkdirAll(filepath.Dir(webPath), 0755)
		ioutil.WriteFile(webPath, []byte(resp), 0644)

		_, err = m.client.Accept(ctx, challenge)
		if err != nil {
			return nil, err
		}

		_, err = m.client.WaitAuthorization(ctx, z.URI)
		if err != nil {
			return nil, err
		}
	}
	fmt.Println("success")
	return m.client.WaitOrder(ctx, order.URI)
}

// validateCert parses a cert chain provided as der argument and verifies the leaf
// and der[0] correspond to the private key, the domain and key type match, and
// expiration dates are valid. It doesn't do any revocation checking.
//
// The returned value is the verified leaf cert.
func validateCert(der [][]byte, domain string, key crypto.Signer, now time.Time) error {
	// parse public part(s)
	var n int
	for _, b := range der {
		n += len(b)
	}
	pub := make([]byte, n)
	n = 0
	for _, b := range der {
		n += copy(pub[n:], b)
	}
	x509Cert, err := x509.ParseCertificates(pub)
	if err != nil || len(x509Cert) == 0 {
		return errors.New("acme/autocert: no public key found")
	}
	// verify the leaf is not expired and matches the domain name
	leaf := x509Cert[0]
	if now.Before(leaf.NotBefore) {
		return errors.New("acme/autocert: certificate is not valid yet")
	}
	if now.After(leaf.NotAfter) {
		return errors.New("acme/autocert: expired certificate")
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return err
	}
	// ensure the leaf corresponds to the private key and matches the certKey type
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		prv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.N.Cmp(prv.N) != 0 {
			return errors.New("acme/autocert: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		prv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.X.Cmp(prv.X) != 0 || pub.Y.Cmp(prv.Y) != 0 {
			return errors.New("acme/autocert: private key does not match public key")
		}
	default:
		return errors.New("acme/autocert: unknown public key algorithm")
	}
	return nil
}
