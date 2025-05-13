// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package clientcredentials implements the OAuth2.0 "client credentials" token flow,
// also known as the "two-legged OAuth 2.0".
//
// This should be used when the client is acting on its own behalf or when the client
// is the resource owner. It may also be used when requesting access to protected
// resources based on an authorization previously arranged with the authorization
// server.
//
// See https://tools.ietf.org/html/rfc6749#section-4.4
package clientcredentials // import "golang.org/x/oauth2/clientcredentials"

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/internal"
)

// Config describes a 2-legged OAuth2 flow, with both the
// client application information and the server's endpoint URLs.
type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// ClientSecret is the application's secret.
	ClientSecret string

	// TokenURL is the resource server's token endpoint
	// URL. This is a constant specific to each server.
	TokenURL string

	// Scopes specifies optional requested permissions.
	Scopes []string

	// EndpointParams specifies additional parameters for requests to the token endpoint.
	EndpointParams url.Values

	// AuthStyle optionally specifies how the endpoint wants the
	// client ID & client secret sent. The zero value means to
	// auto-detect.
	AuthStyle oauth2.AuthStyle

	// KeyProvider enables DPoP support when the authorization server
	// advertises it.
	KeyProvider oauth2.KeyProvider

	dpopOnce      sync.Once
	dpopSupported bool

	// authStyleCache caches which auth style to use when Endpoint.AuthStyle is
	// the zero value (AuthStyleAutoDetect).
	authStyleCache internal.LazyAuthStyleCache
}

// Token uses client credentials to retrieve a token.
//
// The provided context optionally controls which HTTP client is used. See the [oauth2.HTTPClient] variable.
func (c *Config) Token(ctx context.Context) (*oauth2.Token, error) {
	return c.TokenSource(ctx).Token()
}

// Client returns an HTTP client using the provided token.
// The token will auto-refresh as necessary.
//
// The provided context optionally controls which HTTP client
// is returned. See the [oauth2.HTTPClient] variable.
//
// The returned [http.Client] and its Transport should not be modified.
func (c *Config) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, c.TokenSource(ctx))
}

// TokenSource returns a [oauth2.TokenSource] that returns t until t expires,
// automatically refreshing it as necessary using the provided context and the
// client ID and client secret.
//
// Most users will use [Config.Client] instead.
func (c *Config) TokenSource(ctx context.Context) oauth2.TokenSource {
	source := &tokenSource{
		ctx:  ctx,
		conf: c,
	}
	return oauth2.ReuseTokenSource(nil, source)
}

type tokenSource struct {
	ctx  context.Context
	conf *Config
}

func (c *Config) supportsDPoP(ctx context.Context) bool {
	if c.KeyProvider == nil {
		return false
	}
	c.dpopOnce.Do(func() {
		c.dpopSupported = serverSupportsDPoP(ctx, c.TokenURL)
	})
	return c.dpopSupported
}

var dpopCache sync.Map

func serverSupportsDPoP(ctx context.Context, tokenURL string) bool {
	u, err := url.Parse(tokenURL)
	if err != nil {
		return false
	}
	key := u.Scheme + "://" + u.Host
	if v, ok := dpopCache.Load(key); ok {
		return v.(bool)
	}
	paths := []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"}
	for _, p := range paths {
		metaURL := key + p
		req, _ := http.NewRequestWithContext(ctx, "GET", metaURL, nil)
		res, err := internal.ContextClient(ctx).Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 {
			continue
		}
		var m struct {
			Algs []string `json:"dpop_signing_alg_values_supported"`
		}
		if json.Unmarshal(body, &m) == nil && len(m.Algs) > 0 {
			dpopCache.Store(key, true)
			return true
		}
	}
	dpopCache.Store(key, false)
	return false
}

// Token refreshes the token by using a new client credentials request.
// tokens received this way do not include a refresh token
func (c *tokenSource) Token() (*oauth2.Token, error) {
	v := url.Values{
		"grant_type": {"client_credentials"},
	}
	if len(c.conf.Scopes) > 0 {
		v.Set("scope", strings.Join(c.conf.Scopes, " "))
	}
	for k, p := range c.conf.EndpointParams {
		// Allow grant_type to be overridden to allow interoperability with
		// non-compliant implementations.
		if _, ok := v[k]; ok && k != "grant_type" {
			return nil, fmt.Errorf("oauth2: cannot overwrite parameter %q", k)
		}
		v[k] = p
	}

	var proof string
	if c.conf.supportsDPoP(c.ctx) {
		v.Set("token_type", "DPoP")
		proof, _ = dpopProof("POST", c.conf.TokenURL, c.conf.KeyProvider)
	}
	tk, err := internal.RetrieveToken(c.ctx, c.conf.ClientID, c.conf.ClientSecret, c.conf.TokenURL, v, internal.AuthStyle(c.conf.AuthStyle), c.conf.authStyleCache.Get(), proof)
	if err != nil {
		if rErr, ok := err.(*internal.RetrieveError); ok {
			return nil, (*oauth2.RetrieveError)(rErr)
		}
		return nil, err
	}
	t := &oauth2.Token{
		AccessToken:  tk.AccessToken,
		TokenType:    tk.TokenType,
		RefreshToken: tk.RefreshToken,
		Expiry:       tk.Expiry,
	}
	return t.WithExtra(tk.Raw), nil
}
