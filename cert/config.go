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
	"text/template"
)

// Config describes the certificate data for a web server, potentially serving
// more than one site.
type Config struct {
	AccountDir   string
	ContactEmail string `yaml:",omitempty"`

	DefaultSiteKeyFile  string `yaml:",omitempty"`
	DefaultSiteCertFile string `yaml:",omitempty"`
	DefaultWebRoot      string `yaml:",omitempty"`
	Sites               []*ConfigSite

	domainIdx    map[string]int
	keyFileTmpl  *template.Template
	certFileTmpl *template.Template
	webRootTmpl  *template.Template
}

// ConfigSite describes the certificate data for a single domain.
type ConfigSite struct {
	Name     string
	Domain   string
	KeyFile  string `yaml:",omitempty"`
	CertFile string `yaml:",omitempty"`
	WebRoot  string `yaml:",omitempty"`
}

// GetKeyFileName returns the file name for the private key of `domain`.
func (c *Config) GetKeyFileName(domain string) (string, error) {
	i, err := c.getDomainIndex(domain)
	if err != nil {
		return "", err
	}

	if c.Sites[i].KeyFile != "" {
		return c.Sites[i].KeyFile, nil
	}

	if c.keyFileTmpl == nil {
		tmpl := template.New("keyFile")
		tmpl, err := tmpl.Parse(c.DefaultSiteKeyFile)
		if err != nil {
			return "", err
		}
		c.keyFileTmpl = tmpl
	}

	return c.runTemplate(c.keyFileTmpl, i)
}

// GetCertFileName returns the file name for the certificate of site `i`.
func (c *Config) GetCertFileName(domain string) (string, error) {
	i, err := c.getDomainIndex(domain)
	if err != nil {
		return "", err
	}

	if c.Sites[i].CertFile != "" {
		return c.Sites[i].CertFile, nil
	}

	if c.certFileTmpl == nil {
		tmpl := template.New("certFile")
		tmpl, err := tmpl.Parse(c.DefaultSiteCertFile)
		if err != nil {
			return "", err
		}
		c.certFileTmpl = tmpl
	}

	return c.runTemplate(c.certFileTmpl, i)
}

// GetWebRoot returns the path of directory which corresponds to the
// root of the file tree served by site `i`.
func (c *Config) GetWebRoot(domain string) (string, error) {
	i, err := c.getDomainIndex(domain)
	if err != nil {
		return "", err
	}

	if c.Sites[i].WebRoot != "" {
		return c.Sites[i].WebRoot, nil
	}

	if c.webRootTmpl == nil {
		tmpl := template.New("webRoot")
		tmpl, err := tmpl.Parse(c.DefaultWebRoot)
		if err != nil {
			return "", err
		}
		c.webRootTmpl = tmpl
	}

	return c.runTemplate(c.webRootTmpl, i)
}

func (c *Config) getDomainIndex(domain string) (int, error) {
	if c.domainIdx == nil {
		c.domainIdx = make(map[string]int)
		for i, site := range c.Sites {
			c.domainIdx[site.Domain] = i
		}
	}

	idx, ok := c.domainIdx[domain]
	if !ok {
		return -1, &DomainError{
			Domain:  domain,
			Problem: "not in configuration file",
		}
	}
	return idx, nil
}

func (c *Config) runTemplate(tmpl *template.Template, i int) (string, error) {
	buf := &bytes.Buffer{}
	err := tmpl.Execute(buf, map[string]interface{}{
		"Config": c,
		"Site":   c.Sites[i],
	})
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
