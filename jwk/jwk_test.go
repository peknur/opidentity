package jwk

import (
	"testing"
	"time"
)

var ISBKeyEndpoint = "https://isb-test.op.fi/jwks/broker"

func TestKeyStore(t *testing.T) {
	k := NewKeyStore(ISBKeyEndpoint, 5*time.Minute)
	if err := k.Refresh(); err != nil {
		t.Error(err)
	}
	if len(k.Keys) < 1 {
		t.Error("key store is empty")
	}
	if _, err := k.GetPublicKey(k.Keys[0].ID); err != nil {
		t.Error(err)
	}
}
