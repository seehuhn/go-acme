package cert

import (
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// https://letsencrypt.org/docs/rate-limits/

func updateQuotaCerts(domains []string) error {
	// A certificate is considered a renewal (or a duplicate) of an earlier
	// certificate if it contains the exact same set of hostnames, ignoring
	// capitalization and ordering of hostnames.
	domains = append([]string{}, domains...)
	for i, domain := range domains {
		domains[i] = strings.ToLower(domain)
	}
	sort.Strings(domains)

	if isRenewal(domains) {
		// Renewals are subject to a Duplicate Certificate limit of 5 per week.

		// TODO(voss): implement this
	} else {
		// The main limit is Certificates per Registered Domain (50 per week)
		rr := make(map[string]bool)
		for _, domain := range domains {
			registered, err := publicsuffix.EffectiveTLDPlusOne(domain)
			if err != nil {
				return err
			}
			rr[registered] = true
		}
		// TODO(voss): implement this
		_ = rr
	}

	return nil
}

func updateQuotaFailed(domain string) error {
	// There is a Failed Validation limit of 5 failures per account, per
	// hostname, per hour.

	// TODO(voss): implement this
	return nil
}

func isRenewal(domains []string) bool {
	// TODO(voss): implement this
	return false
}
