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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

// Config describes the certificate data for a web server, serving one or
// more domains.
type Config struct {
	AccountDir   string
	ContactEmail string `yaml:",omitempty"`

	DefaultSiteKeyFile  string `yaml:",omitempty"`
	DefaultSiteCertFile string `yaml:",omitempty"`
	DefaultWebRoot      string `yaml:",omitempty"`
	Sites               []*ConfigSite

	domainSite   map[string]*ConfigSite
	keyFileTmpl  *template.Template
	certFileTmpl *template.Template
	webRootTmpl  *template.Template
}

// ConfigSite describes the certificate data for a single domain.
type ConfigSite struct {
	Domain   string
	TLSPort  int    `yaml:",omitempty"` // default is 443
	UseKeyOf string `yaml:",omitempty"`
	KeyFile  string `yaml:",omitempty"`
	CertFile string `yaml:",omitempty"`
	WebRoot  string `yaml:",omitempty"`

	testingHost string // host:port where webroot can be accessed via HTTP
}

// Domains returns all domain names in the configuration data.
func (c *Config) Domains() []string {
	dd := make([]string, len(c.Sites))
	for i, site := range c.Sites {
		dd[i] = site.Domain
	}
	return dd
}

// CertDomains returns a list of certificates the Config describes. Each
// elements of the returned slice is a list of domain names to be used for a
// single certificate.  The first domain name is the one which holds
// information about the key and certificate file names.
func (c *Config) CertDomains() ([][]string, error) {
	head := make(map[string][]string)
	tails := make(map[string][]string)
	for _, site := range c.Sites {
		domain := site.Domain

		target := site.UseKeyOf
		redirects := target != ""
		hasKey := site.KeyFile != "" || site.CertFile != ""
		if redirects && hasKey {
			return nil, &DomainError{
				Domain:  domain,
				Problem: "UseKeyOf and KeyFile/CertFile are mutually exclusive",
			}
		}

		if redirects {
			tails[target] = append(tails[target], domain)
		} else {
			head[domain] = []string{domain}
		}
	}
	for domain, tail := range tails {
		if head[domain] == nil {
			// This case includes both, invalid domain names and domains which
			// have a UseKeyOf of their own.
			return nil, &DomainError{
				Domain:  domain,
				Problem: "invalid target for UseKeyOf",
			}
		}
		head[domain] = append(head[domain], tail...)
	}

	var res [][]string
	for _, domains := range head {
		res = append(res, domains)
	}
	sort.Slice(res, func(i, j int) bool {
		return stringSliceLess(res[i], res[j])
	})
	return res, nil
}

// GetTLSPort returns the TCP port where TLS connections using the site
// certificate can be made.
func (c *Config) GetTLSPort(domain string) (int, error) {
	site, err := c.getDomainSite(domain)
	if err != nil {
		return 0, err
	}

	port := site.TLSPort
	if port == 0 {
		port = 443
	}
	return port, nil
}

// GetKeyFileName returns the file name for the private key of `domain`.
func (c *Config) GetKeyFileName(domain string) (string, error) {
	site, err := c.getDomainSite(domain)
	if err != nil {
		return "", err
	}

	if site.UseKeyOf != "" {
		return "", errNoKey
	}

	if site.KeyFile != "" {
		return site.KeyFile, nil
	}

	if c.keyFileTmpl == nil {
		tmpl := template.New("keyFile")
		tmpl, err := tmpl.Parse(c.DefaultSiteKeyFile)
		if err != nil {
			return "", err
		}
		c.keyFileTmpl = tmpl
	}

	return c.runTemplate(c.keyFileTmpl, site)
}

// GetCertFileName returns the file name for the certificate `domain`.
func (c *Config) GetCertFileName(domain string) (string, error) {
	site, err := c.getDomainSite(domain)
	if err != nil {
		return "", err
	}

	if site.UseKeyOf != "" {
		return "", errNoKey
	}

	if site.CertFile != "" {
		return site.CertFile, nil
	}

	if c.certFileTmpl == nil {
		tmpl := template.New("certFile")
		tmpl, err := tmpl.Parse(c.DefaultSiteCertFile)
		if err != nil {
			return "", err
		}
		c.certFileTmpl = tmpl
	}

	return c.runTemplate(c.certFileTmpl, site)
}

// GetWebRoot returns the path of directory which corresponds to the root of
// the file tree served for `domain`.  Only paths starting with
// `/.well-known/acme-challenge/` are required to work.
func (c *Config) GetWebRoot(domain string) (string, error) {
	site, err := c.getDomainSite(domain)
	if err != nil {
		return "", err
	}

	if site.WebRoot != "" {
		return site.WebRoot, nil
	}

	if c.webRootTmpl == nil {
		if c.DefaultWebRoot == "" {
			return "", &DomainError{
				Domain:  domain,
				Problem: "WebRoot not set and no default",
			}
		}

		tmpl := template.New("webRoot")
		tmpl, err := tmpl.Parse(c.DefaultWebRoot)
		if err != nil {
			return "", err
		}
		c.webRootTmpl = tmpl
	}

	return c.runTemplate(c.webRootTmpl, site)
}

// PublishFile puts a file with the given contents on the web server.
// Returns the created file name (to be used when later removing the file)
// and an error, if any.
func (c *Config) PublishFile(domain, path string, contents []byte) (string, error) {
	root, err := c.GetWebRoot(domain)
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

// TestChallenge tries to publish and read back a challenge response file for
// the given domain.
func (c *Config) TestChallenge(domain string) error {
	token := make([]byte, 8)
	_, err := io.ReadFull(rand.Reader, token)
	if err != nil {
		return err
	}
	tokenStr := base64.RawURLEncoding.EncodeToString(token)
	urlPath := path.Join(".well-known/acme-challenge", "jvcert-"+tokenStr)
	fname, err := c.PublishFile(domain, urlPath, token)
	if err != nil {
		return &DomainError{
			Domain:  domain,
			Problem: "cannot publish file",
			Err:     err,
		}
	}
	defer os.Remove(fname)

	httpDomain := domain
	if site, _ := c.getDomainSite(domain); site != nil && site.testingHost != "" {
		httpDomain = site.testingHost
	}
	resp, err := http.Get("http://" + httpDomain + "/" + urlPath)
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

	if !bytes.Equal(token, body) {
		return &DomainError{
			Domain:  domain,
			Problem: "challenge response body corrupted",
		}
	}

	return nil
}

func (c *Config) getDomainSite(domain string) (*ConfigSite, error) {
	if c.domainSite == nil {
		c.domainSite = make(map[string]*ConfigSite)
		for i, site := range c.Sites {
			c.domainSite[site.Domain] = c.Sites[i]
		}
	}

	idx, ok := c.domainSite[domain]
	if !ok {
		return nil, &DomainError{
			Domain:  domain,
			Problem: "not in configuration file",
		}
	}
	return idx, nil
}

func (c *Config) certDir() string {
	return filepath.Join(c.AccountDir, "certs")
}

func (c *Config) runTemplate(tmpl *template.Template, site *ConfigSite) (string, error) {
	domain := site.Domain
	noWWW := strings.TrimPrefix(domain, "www.")
	first := strings.SplitN(noWWW, ".", 2)[0]
	buf := &bytes.Buffer{}
	// TODO(voss): also split at publicsuffix?
	err := tmpl.Execute(buf, map[string]interface{}{
		"Domain": domain,
		"NoWWW":  noWWW,
		"First":  first,
	})
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
