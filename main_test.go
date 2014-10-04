package oauthv

import (
	"github.com/garyburd/go-oauth/oauth"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	testURL = `http://localhost:8080`
)

const (
	testAppSecret    = `ConsumerSecret`
	testAppToken     = `ConsumerKey`
	testClientSecret = `ClientSecret`
	testClientToken  = `ClientToken`
)

var testClient = oauth.Client{
	Credentials: oauth.Credentials{
		Token:  testAppToken,
		Secret: testAppSecret,
	},
}

var testRequest = oauth.Credentials{
	Token:  testClientToken,
	Secret: testClientSecret,
}

func TestSampleVerifyHeader(t *testing.T) {
	form := url.Values{"maxResults": {"100"}}

	// The last element of path contains a "/".
	path := "/document/encoding%2gizp"

	// Create the request with the temporary path "/".
	req, err := http.NewRequest("GET", "http://api.example.com/", strings.NewReader(form.Encode()))

	if err != nil {
		t.Fatal(err)
	}

	// Overwrite the temporary path with the actual request path.
	req.URL.Opaque = path

	// Sign the request.
	header := testClient.AuthorizationHeader(&testRequest, "GET", req.URL, form)

	var auth *Authorization
	var valid bool

	if auth, err = Parse(header); err != nil {
		t.Fatal(err)
	}

	auth.SetClientSecret(testClient.Credentials.Secret)
	auth.SetRequestSecret(testRequest.Secret)

	if valid, err = auth.ValidateRequest("GET", req.URL, form); err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Fatal(`Expecting request to be valid.`)
	}
}
