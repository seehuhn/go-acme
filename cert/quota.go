// seehuhn.de/go/acme - renew and manage server certificates
// Copyright (C) 2024  Jochen Voss <voss@seehuhn.de>
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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// https://letsencrypt.org/docs/rate-limits/

func (m *Manager) updateQuotaCerts(cert *x509.Certificate, chainDER [][]byte) error {
	// Renewals are subject to a Duplicate Certificate limit of 5 per week.
	// A certificate is considered a renewal (or a duplicate) of an earlier
	// certificate if it contains the exact same set of hostnames, ignoring
	// capitalization and ordering of hostnames.
	domains := append([]string{}, cert.DNSNames...)
	for i, domain := range domains {
		domains[i] = strings.ToLower(domain)
	}
	sort.Strings(domains)
	keyBytes := sha256.Sum256([]byte(strings.Join(domains, ",")))
	key := base64.RawURLEncoding.EncodeToString(keyBytes[:])
	renewalDir := filepath.Join(m.config.certDir(), "renewals", key)
	fileName := cert.NotBefore.UTC().Format("20060102-150405.pem")
	fullName := filepath.Join(renewalDir, fileName)

	isRenewal, err := isDir(renewalDir)
	if err != nil {
		return err
	} else if !isRenewal {
		err := os.MkdirAll(renewalDir, 0755)
		if err != nil {
			return err
		}
	}
	err = writePEM(fullName, chainDER, "CERTIFICATE", 0644)
	if err != nil {
		return err
	}

	if !isRenewal {
		// The main limit is Certificates per Registered Domain (50 per week)
		rr := make(map[string]bool)
		for _, domain := range domains {
			registered, err := publicsuffix.EffectiveTLDPlusOne(domain)
			if err != nil {
				return err
			}
			rr[registered] = true
		}
		certDir := filepath.Join(m.config.certDir(), "new")
		for registered := range rr {
			domainDir := filepath.Join(certDir, registered)
			err := os.MkdirAll(domainDir, 0755)
			if err != nil {
				return err
			}

			// TODO(voss): do I need to worry about collisions, in case
			// somebody registers two sub-domains in one run?
			certName := filepath.Join(domainDir, fileName)
			err = os.Link(fullName, certName)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func updateQuotaFailed(now time.Time, domain string) error {
	// There is a Failed Validation limit of 5 failures per account, per
	// hostname, per hour.

	// TODO(voss): implement this
	return nil
}
