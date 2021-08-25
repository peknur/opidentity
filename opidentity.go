package opidentity

// https://github.com/op-developer/Identity-Service-Broker-API
import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v3"
)

const ClientAssertionClaimExpiration = 600
const responseTypeCode = "code"
const promptTypeConcent = "consent"

// Auth attributes for /oauth/authorize
// https://github.com/op-developer/Identity-Service-Broker-API#7-getpost-oauthauthorize
type Auth struct {
	ClientID     string `json:"client_id"`
	Scope        string `json:"scope"`
	RedirectURL  string `json:"redirect_uri"`
	ResponseType string `json:"response_type"`    // value must be code
	Nonce        string `json:"nonce"`            // make sure that the nonce attribute in the ID Token matches (mitigate replay attacks)
	State        string `json:"state"`            // state between request and callback (eg session id)
	Locales      string `json:"ui_locales"`       // interface language
	Prompt       string `json:"prompt,omitempty"` // can be set to consent to indicate that the user should be asked to consent to personal data being transferred
}

// ClientAssertion attributes for /oauth/token
// https://github.com/op-developer/Identity-Service-Broker-API#8-post-oauthtoken
type ClientAssertion struct {
	Issuer           string `json:"iss"` // This must contain the client_id.
	Subject          string `json:"sub"` // This must contain the client_id.
	Audience         string `json:"aud"` // The aud (audience) Claim. This must match the ISB's token endpoint URL.
	JWTID            string `json:"jti"` // A unique identifier for JWS tokens, which can be used to prevent reuse of the token. These identifiers must only be used once. ISB checks if this jti has already been used and if it has ISB will respond with an error.
	Expiration       int64  `json:"exp"` // time for the token. This is seconds since UNIX epoch (UTC). Suggested time is 600 seconds in the future. ISB checks that the JWS has not expired. If it has expired the ISB will respond with an error.
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Access attributes returnned from /oauth/token
// https://github.com/op-developer/Identity-Service-Broker-API#8-post-oauthtoken
type Access struct {
	Token            string `json:"access_token"`
	Type             string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Identity attributes decoded from ID token
// https://github.com/op-developer/Identity-Service-Broker-API#9-identity-token
type Identity struct {
	Audience             string `json:"aud"`   // Audience this ID Token is intended for. It MUST contain the SP client_id
	Expiration           int64  `json:"exp"`   // Expiration time in seconds since UNIX epoch on or after which the ID Token MUST NOT be accepted for processing.
	Nonce                string `json:"nonce"` // Case sensitive string from the authentication request to associate an end-user with an ID token and to mitigate replay attacks
	Birthdate            string `json:"birthdate"`
	GivenName            string `json:"given_name"`
	FamilyName           string `json:"family_name"`
	Name                 string `json:"name"`                   // Family name and given name
	PersonalIdentityCode string `json:"personal_identity_code"` // The Finnish personal identity code
}

func (i *Identity) IsValid() error {
	if i.Expiration < time.Now().Unix() {
		return errors.New("identity has expired")
	}
	return nil
}

type PublicKeyProvider interface {
	GetPublicKey(keyID string) (*rsa.PublicKey, error)
}

type Client struct {
	ID                       string
	EncryptionKey            *rsa.PrivateKey
	SigningKey               *rsa.PrivateKey
	AuthURL                  string
	TokenURL                 string
	CallbackURL              string
	Locales                  string
	AssertionClaimExpiration int64
	KeyStore                 PublicKeyProvider
}

func (c *Client) NewAuthToken(scope string, state string, nonce string, promptConcent bool) (string, error) {
	var prompt string
	if promptConcent {
		prompt = promptTypeConcent
	}
	payload, err := json.Marshal(Auth{
		ClientID:     c.ID,
		Scope:        scope,
		RedirectURL:  c.CallbackURL,
		ResponseType: responseTypeCode,
		Nonce:        nonce,
		State:        state,
		Locales:      c.Locales,
		Prompt:       prompt,
	})
	if err != nil {
		return "", err
	}
	return NewSignature(payload, c.SigningKey)
}

func (c *Client) NewIdentityFromAuthorizationCode(authorizationCode string) (Identity, error) {
	at, err := c.NewAccessFromAuthorizationCode(authorizationCode)
	if err != nil {
		return Identity{}, err
	}
	return DecodeIdentityToken(at.IDToken, c.EncryptionKey, c.KeyStore)
}

func (c *Client) NewAccessFromAuthorizationCode(authorizationCode string) (Access, error) {
	a := Access{}

	clientAssertionToken, err := c.EncodeClientAssertionToken(CreateRandomToken(32))
	if err != nil {
		return a, err
	}
	val := url.Values{}
	val.Add("code", authorizationCode)
	val.Add("grant_type", "authorization_code")
	val.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	val.Add("client_assertion", clientAssertionToken)
	data := val.Encode()
	req, err := http.NewRequest("POST", c.TokenURL, strings.NewReader(data))
	if err != nil {
		return a, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data)))
	req.Header.Set("Accept", "application/json")
	cli := &http.Client{
		Timeout: 15 * time.Second,
	}
	res, err := cli.Do(req)
	if err != nil {
		return a, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return a, fmt.Errorf("GET %s returned status code %d", c.TokenURL, res.StatusCode)
	}
	err = json.NewDecoder(res.Body).Decode(&a)
	return a, err
}

func (c *Client) EncodeClientAssertionToken(tokenID string) (string, error) {
	clientAssertion, err := json.Marshal(ClientAssertion{
		Issuer:     c.ID,
		Subject:    c.ID,
		Audience:   c.CallbackURL,
		JWTID:      tokenID,
		Expiration: time.Now().Unix() + c.AssertionClaimExpiration,
	})
	if err != nil {
		return "", err
	}
	return NewSignature(clientAssertion, c.SigningKey)
}

func DecodeIdentityToken(token string, encryptionKey *rsa.PrivateKey, k PublicKeyProvider) (Identity, error) {
	id := Identity{}

	jwe, err := jose.ParseEncrypted(token)
	if err != nil {
		return id, err
	}
	signed, err := jwe.Decrypt(encryptionKey)
	if err != nil {
		return id, err
	}

	jws, err := jose.ParseSigned(string(signed))
	if err != nil {
		return id, err
	}
	if len(jws.Signatures) != 1 {
		return id, errors.New("expecting only one signature")
	}
	pub, err := k.GetPublicKey(jws.Signatures[0].Header.KeyID)
	if pub == nil {
		return id, err
	}

	idObject, err := jws.Verify(pub)
	if err != nil {
		return id, err
	}

	err = json.Unmarshal([]byte(idObject), &id)
	if err != nil {
		return id, err
	}

	return id, id.IsValid()
}

// NewSignature signs payload and returns serialized JWS token
func NewSignature(payload []byte, signingKey *rsa.PrivateKey) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, nil)
	if err != nil {
		return "", err
	}
	object, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}
