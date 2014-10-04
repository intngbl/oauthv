// Copyright (c) 2014 Intangible Investments S.A.P.I. de C.V,
// https://intangible.mx
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Package oauthv provides methods for authenticating OAuth 1.0 messages.
package oauthv

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"github.com/garyburd/go-oauth/oauth"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	reKeyValue = regexp.MustCompile(`(oauth_[a-z_-]*)=(:?"([^"]*)"|([^,]*))`)
)

const (
	// SignatureMethodHMACSHA1 is the HMAC-SHA1 supported message authentication.
	SignatureMethodHMACSHA1 = `HMAC-SHA1`
)

const (
	oauthPrefix = `OAuth `
)

var (
	// ErrMissingPrefix is returned when the OAuth header does not have a "OAuth
	// " prefix.
	ErrMissingPrefix = errors.New(`Expecting "OAuth" prefix.`)

	// ErrUnsupportedSignatureMethod is returned when the OAuth header contains
	// an unsupported MAC.
	ErrUnsupportedSignatureMethod = errors.New(`Unsupported signature method.`)

	// ErrSignatureMismatch is returned whtn the calculated signature differs
	// from the message's signature.
	ErrSignatureMismatch = errors.New(`Signature mismatch.`)

	// ErrMissingClientSecret is returned when the user attempts to validate a
	// message without providing a client's secret.
	ErrMissingClientSecret = errors.New(`Missing client's secret.`)

	// ErrMissingRequestSecret is returned when the user attempts to validate a
	// message without providing a request's secret.
	ErrMissingRequestSecret = errors.New(`Missing request's secret.`)
)

// Authorization struct provides methods for message authentication.
type Authorization struct {
	Client  oauth.Credentials
	Request oauth.Credentials

	Nonce           string
	Signature       string
	SignatureMethod string
	Timestamp       uint
	Version         string
}

// Parse expects the content of an OAuth 1.0 authorization header and returns a
// populated *Authorization struct.
func Parse(header string) (auth *Authorization, err error) {

	if strings.HasPrefix(header, oauthPrefix) == false {
		err = ErrMissingPrefix
		return
	}

	auth = new(Authorization)

	matches := reKeyValue.FindAllStringSubmatch(header, -1)

	for _, match := range matches {
		key, value := match[1], match[3]
		if value, err = url.QueryUnescape(value); err != nil {
			return nil, err
		}
		switch key {
		case `oauth_consumer_key`:
			auth.Client.Token = value
		case `oauth_nonce`:
			auth.Nonce = value
		case `oauth_signature`:
			auth.Signature = value
		case `oauth_signature_method`:
			auth.SignatureMethod = value
		case `oauth_timestamp`:
			i, _ := strconv.Atoi(value)
			auth.Timestamp = uint(i)
		case `oauth_token`:
			auth.Request.Token = value
		case `oauth_version`:
			auth.Version = value
		}
	}

	return
}

// SetClientSecret expects the value of the app's secret.
func (auth *Authorization) SetClientSecret(s string) {
	auth.Client.Secret = s
}

// SetRequestSecret expects the value of the request's temporary secret.
func (auth *Authorization) SetRequestSecret(s string) {
	auth.Request.Secret = s
}

// ValidateRequest expects
func (auth *Authorization) ValidateRequest(method string, u *url.URL, form url.Values) (bool, error) {

	// Portions of this code where taken from
	// https://github.com/garyburd/go-oauth, released under the Apache License
	// 2.0.

	if auth.Client.Secret == "" {
		return false, ErrMissingClientSecret
	}

	if auth.Request.Secret == "" {
		return false, ErrMissingRequestSecret
	}

	var key bytes.Buffer
	key.Write(encode(auth.Client.Secret, false))
	key.WriteByte('&')
	key.Write(encode(auth.Request.Secret, false))

	var sum []byte
	switch auth.SignatureMethod {
	case SignatureMethodHMACSHA1:
		h := hmac.New(sha1.New, key.Bytes())
		writeBaseString(h, method, u, form, auth.paramsMap())
		sum = h.Sum(nil)
	default:
		return false, ErrUnsupportedSignatureMethod
	}

	encodedSum := make([]byte, base64.StdEncoding.EncodedLen(len(sum)))
	base64.StdEncoding.Encode(encodedSum, sum)

	if string(encodedSum) == auth.Signature {
		return true, nil
	}

	return false, ErrSignatureMismatch
}

func (auth *Authorization) paramsMap() map[string]string {
	m := map[string]string{
		"oauth_consumer_key":     auth.Client.Token,
		"oauth_signature_method": auth.SignatureMethod,
		"oauth_timestamp":        strconv.FormatInt(int64(auth.Timestamp), 10),
		"oauth_version":          auth.Version,
		"oauth_nonce":            auth.Nonce,
		"oauth_token":            auth.Request.Token,
	}
	return m
}
