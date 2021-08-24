package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"opidentity"
	"opidentity/jwk"
	"text/template"
	"time"
)

//go:embed static/*
var staticDir embed.FS

//go:embed templates/*
var templateDir embed.FS

// Test credentials
var ClientID = "saippuakauppias"
var Scope = "openid personal_identity_code profile"
var AuthURL = "https://isb-test.op.fi/oauth/authorize"
var TokenURL = "https://isb-test.op.fi/oauth/token"
var CallbackURL = "http://localhost:8000/callback"
var ISBKeyEndpoint = "https://isb-test.op.fi/jwks/broker"
var Locales = "fi"

func main() {
	addr := ":8000"
	log.Printf("start listening %s", addr)
	if err := RunHTTPServer(addr); err != nil {
		log.Fatal(err)
	}
}

func RunHTTPServer(addr string) error {
	encryptionKey, err := opidentity.NewPrivateKeyFromFile("sandbox-sp-encryption-key.pem")
	if err != nil {
		return err
	}
	signingKey, err := opidentity.NewPrivateKeyFromFile("sandbox-sp-signing-key.pem")
	if err != nil {
		return err
	}
	k := jwk.NewKeyStore(ISBKeyEndpoint, 5*time.Minute)
	if err := k.Refresh(); err != nil {
		return err
	}
	config := opidentity.Client{
		ID:                       ClientID,
		EncryptionKey:            encryptionKey,
		SigningKey:               signingKey,
		AuthURL:                  AuthURL,
		TokenURL:                 TokenURL,
		CallbackURL:              CallbackURL,
		Locales:                  Locales,
		AssertionClaimExpiration: opidentity.ClientAssertionClaimExpiration,
		KeyStore:                 k,
	}
	fileServer := http.FileServer(http.FS(staticDir))
	http.Handle("/static/", fileServer)
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/identify", identifyHandler(&config))
	http.HandleFunc("/callback", callbackHandler(&config))
	http.HandleFunc("/jwks", JWKSHandler)
	return http.ListenAndServe(addr, nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if err := renderTemplate(w, "templates/index.html", nil); err != nil {
		errorHandler(w, r, http.StatusInternalServerError, err)
		return
	}
}

func identifyHandler(c *opidentity.Client) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// make sure that the nonce attribute in the ID Token matches (mitigate replay attacks)
		nonce := opidentity.CreateRandomToken(32)
		// state between request and callback (eg session id)
		state := opidentity.CreateRandomToken(32)

		payload, err := json.Marshal(opidentity.Auth{
			ClientID:     ClientID,
			Scope:        Scope,
			RedirectURL:  c.CallbackURL,
			ResponseType: "code",
			Nonce:        nonce,
			State:        state,
			Locales:      c.Locales,
			Prompt:       "consent",
		})
		if err != nil {
			errorHandler(w, r, http.StatusInternalServerError, err)
			return
		}

		token, err := opidentity.NewSignature(payload, c.SigningKey)
		if err != nil {
			errorHandler(w, r, http.StatusInternalServerError, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%s?request=%s", AuthURL, token), http.StatusTemporaryRedirect)
	}
}

func callbackHandler(c *opidentity.Client) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			errorHandler(w, r, http.StatusInternalServerError, fmt.Errorf("parse form failed: %s", err))
			return
		}
		var state, code, authError string
		if authError = r.Form.Get("error"); authError != "" {
			if authErrorDesc := r.Form.Get("error_description"); authErrorDesc != "" {
				authError = fmt.Sprintf("%s (%s)", authErrorDesc, authError)
			}
			errorHandler(w, r, http.StatusBadRequest, fmt.Errorf("identification failed: %s", authError))
			return
		}
		if state = r.Form.Get("state"); state == "" {
			errorHandler(w, r, http.StatusBadRequest, errors.New("state parameter is missing or empty"))
			return
		}

		if code = r.Form.Get("code"); code == "" {
			errorHandler(w, r, http.StatusBadRequest, errors.New("code parameter is missing or empty"))
			return
		}

		id, err := c.NewIdentityFromAuthorizationCode(code)
		if err != nil {
			errorHandler(w, r, http.StatusBadRequest, err)
			return
		}
		// @todo: check that id.Nonce matches nonce from auth request
		renderTemplate(w, "templates/callback.html", id)
	}
}

func errorHandler(w http.ResponseWriter, r *http.Request, statusCode int, err error) {
	log.Println(err)
	w.WriteHeader(statusCode)
	renderTemplate(w, "templates/error.html", struct {
		Error string
	}{
		Error: fmt.Sprintf("An error occurred, please try again later:\n%s", err),
	})
}

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	errorHandler(w, r, http.StatusNotImplemented, errors.New("not implemented"))
}

func renderTemplate(w io.Writer, fileName string, data interface{}) error {
	t, err := template.ParseFS(templateDir, fileName)
	if err != nil {
		return err
	}
	return t.Execute(w, data)
}
