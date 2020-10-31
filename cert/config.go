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
