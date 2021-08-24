package opidentity

import (
	"testing"
	"time"
)

func TestIdentityExpiration(t *testing.T) {
	i := Identity{Expiration: time.Now().Unix()}
	time.Sleep(1 * time.Second)
	if err := i.IsValid(); err == nil {
		t.Error("identity should be expired")
	}
}

func TestNewSignature(t *testing.T) {
	key, err := NewPrivateKeyFromFile("example/httpd/sandbox-sp-signing-key.pem")
	if err != nil {
		t.Error(err)
	}
	want := "eyJhbGciOiJSUzI1NiJ9.VEVTVA.klvw9HBctNBRHYjJF-N_FPbY2vGzS9IqF7rsuUqr88RHydhdbUgtnQdImEYowe2aWflvfzoXi05i00Q90nssPYFBSkya2np3iXywm5AmLHOQtGDXSAGPmHs4MkXRlW2mQ0s1MT3NJKZIjPgvMwS1sdwdkIAv3xHhk5fZL-4594CgyIGTvIFHEZPlpkM9_L7JCIRTraq7zv8F9wsDs6g_dKdRTcfJDjNVzYep67Nnhusbt-Npe583csCn9ow9M3CLYqSArgjcMkr8e6pDlA0o6mzHG7KDpa4EYNfP-twQTrcl-orGigHDglKGk0VEVv5D3CGAsYZsXr-uhR4sr-4OeA"
	got, err := NewSignature([]byte("TEST"), key)
	if err != nil {
		t.Error(err)
	}
	if want != got {
		t.Errorf("signature mismatch want '%s' got '%s'", want, got)
	}
}
