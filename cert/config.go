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
	UseKeyOf string `yaml:",omitempty"`
	KeyFile  string `yaml:",omitempty"`
	CertFile string `yaml:",omitempty"`
	WebRoot  string `yaml:",omitempty"`
}

// Domains returns all domain names in the configuration data.
func (c *Config) Domains() []string {
	dd := make([]string, len(c.Sites))
	for i, site := range c.Sites {
		dd[i] = site.Domain
	}
	return dd
}

// CertificateDomains returns a list of certificates the Config describes. Each
// elements of the returned slice is a list of domain names to be used for a
// single certificate.  The first domain name is the one which holds
// information about the key and certificate file names.
func (c *Config) CertificateDomains() (map[string][]string, error) {
	res := make(map[string][]string)
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
			res[domain] = []string{domain}
		}
	}
	for domain, tail := range tails {
		if res[domain] == nil {
			// This case includes both, invalid domain names and domains which
			// have a UseKeyOf of their own.
			return nil, &DomainError{
				Domain:  domain,
				Problem: "invalid target for UseKeyOf",
			}
		}
		res[domain] = append(res[domain], tail...)
	}
	return res, nil
}

func oneKeyOf(m map[string]bool) string {
	for key := range m {
		return key
	}
	return ""
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

// GetCertFileName returns the file name for the certificate of site `i`.
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

// GetWebRoot returns the path of directory which corresponds to the
// root of the file tree served by site `i`.
func (c *Config) GetWebRoot(domain string) (string, error) {
	site, err := c.getDomainSite(domain)
	if err != nil {
		return "", err
	}

	if site.WebRoot != "" {
		return site.WebRoot, nil
	}

	if c.webRootTmpl == nil {
		tmpl := template.New("webRoot")
		tmpl, err := tmpl.Parse(c.DefaultWebRoot)
		if err != nil {
			return "", err
		}
		c.webRootTmpl = tmpl
	}

	return c.runTemplate(c.webRootTmpl, site)
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

func (c *Config) runTemplate(tmpl *template.Template, site *ConfigSite) (string, error) {
	domain := site.Domain
	noWWW := strings.TrimPrefix(domain, "www.")
	first := strings.SplitN(noWWW, ".", 2)[0]
	buf := &bytes.Buffer{}
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
