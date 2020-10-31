// seehuhn.de/go/letsencrypt/getcert - a command line tool to manage TLS certificates
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

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"seehuhn.de/go/letsencrypt/cert"
)

// DefaultACMEDirectory is the default ACME Directory URL.
const DefaultACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// DebugACMEDirectory is the ACME v2 Staging Directory URL.
const DebugACMEDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

func main() {
	config := &cert.Config{
		AccountDir:    ".",
		ContactEmail:  "voss@seehuhn.de",
		ACMEDirectory: DebugACMEDirectory,

		SiteRoot:        ".",
		DefaultSiteKey:  "{{.Config.SiteRoot}}/{{.Site.Name}}/keys/private.key",
		DefaultSiteCert: "{{.Config.SiteRoot}}/{{.Site.Name}}/keys/certificate.crt",
		DefaultWebPath:  "{{.Config.SiteRoot}}/{{.Site.Name}}/acme",
		Sites: []*cert.SiteConfig{
			{
				Domain: "test.seehuhn.de",
			},
		},
	}

	ctx := context.TODO()

	m, err := cert.NewManager(ctx, config)
	if err != nil {
		log.Fatal(err)
	} else if m == nil {
		fmt.Println("all certificates are current, nothing to do")
		os.Exit(0)
	}

	err = m.RenewAll(ctx)
	if err != nil {
		log.Fatal(err)
	}
}
