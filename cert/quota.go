package cert

import (
	"golang.org/x/net/publicsuffix"
)

func checkQuota(domains []string) error {
	// https://letsencrypt.org/docs/rate-limits/
	rr := make(map[string]bool)
	for _, domain := range domains {
		registered, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			return err
		}
		rr[registered] = true
	}
	_ = rr
	return nil
}
