package acmeendpoints

var (
	// Let's Encrypt (Live v2)
	LetsEncryptLiveV2 = Endpoint{
		Code:                         "LetsEncryptLiveV2",
		Title:                        "Let's Encrypt (Live v2)",
		DirectoryURL:                 "https://acme-v02.api.letsencrypt.org/directory",
		OCSPURLRegexp:                `^http://ocsp\.int-[^.]+\.letsencrypt\.org\.?/.*$`,
		CertificateURLRegexp:         `^https://acme-v02\.api\.letsencrypt\.org\.?/acme/cert/.*$`,
		CertificateURLTemplate:       `https://acme-v02.api.letsencrypt.org/acme/cert/{{.Certificate.SerialNumber|printf "%036x"}}`,
		DeprecatedDirectoryURLRegexp: `^https://acme-v01\.api\.letsencrypt\.org/directory$`,
		Live: true,
	}

	// Let's Encrypt (Staging v2)
	LetsEncryptStagingV2 = Endpoint{
		Code:                   "LetsEncryptStagingV2",
		Title:                  "Let's Encrypt (Staging v2)",
		DirectoryURL:           "https://acme-staging-v02.api.letsencrypt.org/directory",
		OCSPURLRegexp:          `^http://ocsp\.(staging|stg-int)-[^.]+\.letsencrypt\.org\.?/.*$`,
		CertificateURLRegexp:   `^https://acme-staging-v02\.api\.letsencrypt\.org\.?/acme/cert/.*$`,
		CertificateURLTemplate: `https://acme-staging-v02.api.letsencrypt.org/acme/cert/{{.Certificate.SerialNumber|printf "%036x"}}`,
		Live: false,
	}
)

// Suggested default endpoint.
var DefaultEndpoint = &LetsEncryptLiveV2

var builtinEndpoints = []*Endpoint{
	&LetsEncryptLiveV2,
	&LetsEncryptStagingV2,
}
