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
