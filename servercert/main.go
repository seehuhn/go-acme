// seehuhn.de/go/acme/servercert - a command line tool to manage TLS certificates
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
	"flag"
	"fmt"
	"log"
	"time"

	"seehuhn.de/go/acme/cert"
)

// List prints a table with information about all known certificates to stdout.
func List(m *cert.Manager) error {
	infos, err := m.GetCertInfo()
	if err != nil {
		return err
	}

	fmt.Println("domain               | valid | expiry time  | comment")
	fmt.Println("---------------------+-------+--------------+--------------")
	for _, info := range infos {
		var tStr string
		if !info.Expiry.IsZero() {
			dt := time.Until(info.Expiry)
			if dt <= 0 {
				tStr = "expired"
			} else if dt > 48*time.Hour {
				tStr = fmt.Sprintf("%.1f days", float64(dt)/float64(24*time.Hour))
			} else {
				tStr = dt.Round(time.Second).String()
			}
		}
		fmt.Printf("%-20s | %-5t | %-12s | %s\n", info.Domain, info.IsValid,
			tStr, info.Message)
	}
	return nil
}

// Renew all certificates which are not valid for at least 7 more days.
func Renew(m *cert.Manager) error {
	infos, err := m.GetCertInfo()
	if err != nil {
		return err
	}

	deadline := time.Now().Add(7 * 24 * time.Hour)
	for i, info := range infos {
		if info.IsValid && info.Expiry.After(deadline) {
			fmt.Println(info.Domain, "is still good")
			continue
		}
		fmt.Println("renewing", info.Domain)
		err = m.RenewCertificate(i)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.Parse()

	config := &cert.Config{
		AccountDir:   ".",
		ContactEmail: "voss@seehuhn.de",

		SiteRoot:            ".",
		DefaultSiteKeyFile:  "{{.Config.SiteRoot}}/{{.Site.Name}}/keys/private.key",
		DefaultSiteCertFile: "{{.Config.SiteRoot}}/{{.Site.Name}}/keys/certificate.crt",
		DefaultWebRoot:      "{{.Config.SiteRoot}}/{{.Site.Name}}/acme",
		Sites: []*cert.ConfigSite{
			{
				Name:   "test",
				Domain: "test.seehuhn.de",
			},
			{
				Name:   "torpedo",
				Domain: "torpedo.seehuhn.de",
			},
		},
	}

	m, err := cert.NewManager(config, true)
	if err != nil {
		log.Fatal(err)
	}

	// m.InstallDummyCert(1, 10*time.Second)

	cmd := flag.Arg(0)

	switch cmd {
	case "list":
		err = List(m)
	case "dummy":
		err = m.InstallDummyCertificate(1, time.Hour)
	case "renew":
		err = Renew(m)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}
