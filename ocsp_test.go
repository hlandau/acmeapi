package acmeapi

import (
	"context"
	"crypto/x509"
	"golang.org/x/crypto/ocsp"
	"gopkg.in/hlandau/acmeapi.v2/acmeutils"
	"testing"
)

const testOCSPCerts = `-----BEGIN CERTIFICATE-----
MIIE6DCCA9CgAwIBAgITAPr3OLUNFF72kSERFC+leb00HDANBgkqhkiG9w0BAQsF
ADAfMR0wGwYDVQQDDBRoYXBweSBoYWNrZXIgZmFrZSBDQTAeFw0xNjAxMTcxNjAx
MDBaFw0xNjA0MTYxNjAxMDBaMB4xHDAaBgNVBAMTE2FxMS5saGguZGV2ZXZlci5u
ZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVQT8bs4n6+3QLyehW
GseFUI+xMMlAM0Mrkol0rB2ZbC4rWanxfqG9TE6i/ToEe+9dL7NxpBKXrRnD/4jK
cpDxHbGy+hqx/XZefmpdLK2E7FtO53sE0rDcQVGZ2r4YweumfS6jNoNeNZsMzJ6/
aAeXoz+j+rPJG73NjgWz2BIWwum7AMquq2YeERp3eu5hXQDsZxk6dlNwJ3XVaho7
EZZojQENm2/BRkpr1oLzq5fMKVc+zRGzuoCJqeYH6yYzWG7oUypW+H477pKDfKLE
RGwEoTAAx4SS4HwXYrCftFgfmWw6fFV9L8aqON8ypW9CZ5HCprymypcy+6/n/S7k
ruH3AgMBAAGjggIcMIICGDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFN/DSOGyPtfc
1X8rffIJtSocqMzbMB8GA1UdIwQYMBaAFPt4TxL5YBWDLJ8XfzQZsy426kGJMHgG
CCsGAQUFBwEBBGwwajAzBggrBgEFBQcwAYYnaHR0cDovL29jc3Auc3RhZ2luZy14
MS5sZXRzZW5jcnlwdC5vcmcvMDMGCCsGAQUFBzAChidodHRwOi8vY2VydC5zdGFn
aW5nLXgxLmxldHNlbmNyeXB0Lm9yZy8wHgYDVR0RBBcwFYITYXExLmxoaC5kZXZl
dmVyLm5ldDCB/gYDVR0gBIH2MIHzMAgGBmeBDAECATCB5gYLKwYBBAGC3xMBAQEw
gdYwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIGrBggr
BgEFBQcCAjCBngyBm1RoaXMgQ2VydGlmaWNhdGUgbWF5IG9ubHkgYmUgcmVsaWVk
IHVwb24gYnkgUmVseWluZyBQYXJ0aWVzIGFuZCBvbmx5IGluIGFjY29yZGFuY2Ug
d2l0aCB0aGUgQ2VydGlmaWNhdGUgUG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vbGV0
c2VuY3J5cHQub3JnL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAVkT8U
oD2AJVjtHogCyt7BkPQ+j6zN1zaN9Bd9nI6a7tpAT6B+j6IqB4o2vCFYawiKaDwR
ri06Yi9Ohf1QY50D7P21wzfsRoizHbsmHDPPnlDfFe/R1MzB7jYI1JV4LkjWLpuC
OjTQZs3hIoEbTEBA/TIcwAfS9oMFgk+LgL5B4zQUZgqVp0+A4NNy3J1nBhYC2k2T
6qiE0CeU8bCfR2V2MZ6Az2X8nwWkWwovosDQR0oOWDcACDbDnS6OPMuHtZi7Wtqn
UeMJ3YfZ7VBWzJTmDRPoDdbP92YI8FqRGbA6GO/XzyJvkOKSnc3CDfJ9Od0IeVeV
aC0Q8qLjOhazFhj0
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIJAJzxkS6o1QkIMA0GCSqGSIb3DQEBCwUAMB8xHTAbBgNV
BAMMFGhhcHB5IGhhY2tlciBmYWtlIENBMB4XDTE1MDQwNzIzNTAzOFoXDTI1MDQw
NDIzNTAzOFowHzEdMBsGA1UEAwwUaGFwcHkgaGFja2VyIGZha2UgQ0EwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCCkd5mgXFErJ3F2M0E9dw+Ta/md5i
8TDId01HberAApqmydG7UZYF3zLTSzNjlNSOmtybvrSGUnZ9r9tSQcL8VM6WUOM8
tnIpiIjEA2QkBycMwvRmZ/B2ltPdYs/R9BqNwO1g18GDZrHSzUYtNKNeFI6Glamj
7GK2Vr0SmiEamlNIR5ktAFsEErzf/d4jCF7sosMsJpMCm1p58QkP4LHLShVLXDa8
BMfVoI+ipYcA08iNUFkgW8VWDclIDxcysa0psDDtMjX3+4aPkE/cefmP+1xOfUuD
HOGV8XFynsP4EpTfVOZr0/g9gYQ7ZArqXX7GTQkFqduwPm/w5qxSPTarAgMBAAGj
UDBOMB0GA1UdDgQWBBT7eE8S+WAVgyyfF380GbMuNupBiTAfBgNVHSMEGDAWgBT7
eE8S+WAVgyyfF380GbMuNupBiTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQAd9Da+Zv+TjMv7NTAmliqnWHY6d3UxEZN3hFEJ58IQVHbBZVZdW7zhRktB
vR05Kweac0HJeK91TKmzvXl21IXLvh0gcNLU/uweD3no/snfdB4OoFompljThmgl
zBqiqWoKBJQrLCA8w5UB+ReomRYd/EYXF/6TAfzm6hr//Xt5mPiUHPdvYt75lMAo
vRxLSbF8TSQ6b7BYxISWjPgFASNNqJNHEItWsmQMtAjjwzb9cs01XH9pChVAWn9L
oeMKa+SlHSYrWG93+EcrIH/dGU76uNOiaDzBSKvaehG53h25MHuO1anNICJvZovW
rFo4Uv1EnkKJm3vJFe50eJGhEKlx
-----END CERTIFICATE-----`

func TestOCSP(t *testing.T) {
	b, err := acmeutils.LoadCertificates([]byte(testOCSPCerts))
	if err != nil {
		t.Fatalf("cannot load certificates")
	}

	c0, err := x509.ParseCertificate(b[0])
	if err != nil {
		t.Fatalf("cannot parse certificate")
	}

	c1, err := x509.ParseCertificate(b[1])
	if err != nil {
		t.Fatalf("cannot parse certificate")
	}

	cl := RealmClient{}

	res, _, err := cl.CheckOCSP(context.TODO(), c0, c1)
	if err != nil {
		t.Fatalf("ocsp error: %v", err)
	}

	if res.Status != ocsp.Revoked {
		t.Fatalf("ocsp status should be revoked (1) but is %v", res.Status)
	}
}
