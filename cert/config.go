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

// Config contains the data which describes the certificate management
// framework for a single web server, potentially serving more than one site.
type Config struct {
	AccountDir    string
	ContactEmail  string
	ACMEDirectory string

	SiteRoot        string
	DefaultSiteKey  string
	DefaultSiteCert string
	DefaultWebPath  string
	Sites           []*SiteConfig
}

// SiteConfig contains the data which describes the certificate management
// framework for a single domain.
type SiteConfig struct {
	Domain   string
	KeyPath  string
	CertPath string
	WebPath  string
}
