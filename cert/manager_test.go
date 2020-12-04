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
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"seehuhn.de/go/acme/internal/acmetest"
)

// TestManger does a high-level test by requesting a new certificate and
// then checking whether the received certificate is valid.
func TestManager(t *testing.T) {
	domain := "test.example.com"

	serverRoot := t.TempDir()
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer listener.Close() // this will stop the web server
	go http.Serve(listener, http.FileServer(http.Dir(serverRoot)))

	ca := acmetest.NewCAServer([]string{"tls-alpn-01", "http-01"}, nil)
	defer ca.Close()
	ca.Resolve(domain, listener.Addr().String())

	accountDir := t.TempDir()
	c := &Config{
		AccountDir: accountDir,
		Sites: []*ConfigSite{
			{
				Domain:      domain,
				WebRoot:     serverRoot,
				KeyFile:     filepath.Join(accountDir, "key.pem"),
				CertFile:    filepath.Join(accountDir, "cert.pem"),
				testingHost: listener.Addr().String(),
			},
		},
	}
	m, err := NewManager(c, ca.URL, ca.Roots)
	if err != nil {
		t.Fatal(err)
	}

	err = m.RenewCertificate([]string{domain})
	if err != nil {
		t.Error(err)
	}

	info, err := m.GetCertInfo(domain, time.Now())
	if err != nil {
		t.Error(err)
	} else if !info.IsValid {
		t.Errorf("received invalid certificate: %s", info.Message)
	}
}
