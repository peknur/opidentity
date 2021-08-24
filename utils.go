package opidentity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

func NewPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return NewPrivateKey(data)
}

func NewPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	p, _ := pem.Decode(data)
	if p == nil {
		return nil, errors.New("unable to decode private key data")
	}
	return x509.ParsePKCS1PrivateKey(p.Bytes)
}

func CreateRandomToken(s uint8) string {
	b := make([]byte, s)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}
