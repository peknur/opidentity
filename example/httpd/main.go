package main

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/peknur/opidentity"
	"github.com/peknur/opidentity/jwk"
)

//go:embed static/*
var staticDir embed.FS

//go:embed templates/*
var templateDir embed.FS

func main() {
	// http server listen address
	addr := ":8000"

	// OP test credentials
	clientID := "saippuakauppias"
	authURL := "https://isb-test.op.fi/oauth/authorize"
	tokenURL := "https://isb-test.op.fi/oauth/token"
	callbackURL := "http://localhost:8000/callback"
	isbKeyEndpoint := "https://isb-test.op.fi/jwks/broker"
	locales := "fi"

	var client *opidentity.Client
	var err error

	keyStore := jwk.NewKeyStore(isbKeyEndpoint, 5*time.Minute)
	if err = keyStore.Refresh(); err != nil {
		log.Fatal(err)
	}

	if client, err = opidentity.NewClient(clientID, authURL, tokenURL, callbackURL, locales, "sandbox-sp-encryption-key.pem", "sandbox-sp-signing-key.pem", keyStore); err != nil {
		log.Fatal(err)
	}
	log.Printf("start listening %s", addr)
	if err := RunHTTPServer(addr, client); err != nil {
		log.Fatal(err)
	}
}

func RunHTTPServer(addr string, client *opidentity.Client) error {
	fileServer := http.FileServer(http.FS(staticDir))
	http.Handle("/static/", fileServer)
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/identify", identifyHandler(client))
	http.HandleFunc("/callback", callbackHandler(client))
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

		// set scope of requested information
		scope := "openid personal_identity_code profile"

		// make sure that the nonce attribute in the ID Token matches (mitigate replay attacks)
		nonce := opidentity.CreateRandomToken(32)

		// state between request and callback (eg session id)
		state := opidentity.CreateRandomToken(32)

		token, err := c.NewAuthToken(scope, state, nonce, true)
		if err != nil {
			errorHandler(w, r, http.StatusInternalServerError, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%s?request=%s", c.AuthURL, token), http.StatusTemporaryRedirect)
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
