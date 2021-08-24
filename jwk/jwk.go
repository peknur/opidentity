package jwk

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const keyTypeRSA = "RSA"
const keyUseSignature = "sig"

// JWK (JSON Web Key) has relevant fields to decode RSA public key
// https://www.rfc-editor.org/rfc/rfc7517
type JWK struct {
	ID   string `json:"kid"`
	Type string `json:"kty"`

	// The "use" (public key use) parameter identifies the intended use of the public key.
	// The "use" parameter is employed to indicate whether a public key is used for encrypting (enc) data or verifying the signature (sig) on data.
	// https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
	PublicKeyUse string `json:"use"`

	// The "n" (modulus) parameter contains the modulus value for the RSA public key.
	// It is represented as a Base64urlUInt-encoded value.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1.1
	Modulus string `json:"n"`

	// The "e" (exponent) parameter contains the exponent value for the RSA public key.
	// It is represented as a Base64urlUInt-encoded value.
	// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1.2
	Exponent string `json:"e"`
}

func (k *JWK) Decode() (*rsa.PublicKey, error) {
	if k.Type != keyTypeRSA {
		return nil, fmt.Errorf("key type '%s' not supported", k.Type)
	}
	if k.PublicKeyUse != keyUseSignature {
		return nil, fmt.Errorf("key usage '%s' not supported", k.PublicKeyUse)
	}
	modulus, err := base64.RawURLEncoding.DecodeString(k.Modulus)
	if err != nil {
		return nil, err
	}

	exponent, err := base64.RawURLEncoding.DecodeString(k.Exponent)
	if err != nil {
		return nil, err
	}

	return &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(modulus),
		E: int(big.NewInt(0).SetBytes(exponent).Uint64()),
	}, nil
}

type KeyStore struct {
	URL        string
	TTL        time.Duration
	Keys       []JWK
	lastUpdate time.Time
	mu         sync.Mutex
}

func (k *KeyStore) Refresh() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if time.Since(k.lastUpdate) < k.TTL {
		return nil
	}
	res, err := http.Get(k.URL)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned status code %d", k.URL, res.StatusCode)
	}

	set := struct{ Keys []JWK }{}
	if err = json.NewDecoder(res.Body).Decode(&set); err != nil {
		return err
	}
	k.lastUpdate = time.Now()
	k.Keys = set.Keys
	return err
}

func (k *KeyStore) GetPublicKey(ID string) (*rsa.PublicKey, error) {
	if err := k.Refresh(); err != nil {
		return nil, err
	}
	for _, k := range k.Keys {
		if k.ID == ID {
			return k.Decode()
		}
	}

	return nil, fmt.Errorf("public key with ID '%s' not found", ID)
}

func NewKeyStore(URL string, TTL time.Duration) *KeyStore {
	return &KeyStore{
		URL:        URL,
		TTL:        TTL,
		Keys:       []JWK{},
		lastUpdate: time.Time{},
		mu:         sync.Mutex{},
	}
}
