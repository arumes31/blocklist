package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blocklist/internal/config"

	"github.com/alicebob/miniredis/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

const testEntraTenant = "11111111-1111-1111-1111-111111111111"
const testEntraClient = "22222222-2222-2222-2222-222222222222"

func testEntraConfig(t *testing.T) *config.Config {
	t.Helper()
	secretPath := filepath.Join(t.TempDir(), "client-secret")
	require.NoError(t, os.WriteFile(secretPath, []byte("synthetic-test-secret"), 0600))
	return &config.Config{EntraEnabled: true, EntraTenantID: testEntraTenant,
		EntraClientID: testEntraClient, EntraClientSecretFile: secretPath,
		EntraRedirectURL:   "http://localhost:5050/auth/entra/callback",
		EntraViewerAppRole: "Blocklist.Viewer", EntraModeratorAppRole: "Blocklist.Moderator", EntraEditorAppRole: "Blocklist.Editor"}
}

func TestEntraConfigurationAndMapping(t *testing.T) {
	service, err := NewEntraService(&config.Config{}, nil)
	require.NoError(t, err)
	require.Nil(t, service)
	cache := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})
	t.Cleanup(func() { _ = cache.Close() })
	cfg := testEntraConfig(t)
	service, err = NewEntraService(cfg, cache)
	require.NoError(t, err)
	for _, tc := range []struct {
		claims []string
		want   string
	}{
		{nil, ""}, {[]string{"blocklist.viewer"}, ""}, {[]string{"unknown"}, ""},
		{[]string{"Blocklist.Viewer"}, "viewer"}, {[]string{"Blocklist.Moderator", "Blocklist.Viewer"}, "moderator"},
		{[]string{"Blocklist.Viewer", "Blocklist.Editor"}, "editor"},
	} {
		require.Equal(t, tc.want, service.MapRole(tc.claims))
	}
	for _, redirect := range []string{"http://example.com/auth/entra/callback", "https://example.com/other", "https://user@example.com/auth/entra/callback", "https://example.com/auth/entra/callback?x=1"} {
		cfg.EntraRedirectURL = redirect
		_, err := NewEntraService(cfg, cache)
		require.Error(t, err, redirect)
	}
}

func TestEntraVerifiedFlow(t *testing.T) {
	ctx := context.Background()
	cache := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})
	t.Cleanup(func() { _ = cache.Close() })
	cfg := testEntraConfig(t)
	service, err := NewEntraService(cfg, cache)
	require.NoError(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
	require.NoError(t, err)
	var signedToken, expectedVerifier string
	exchanges := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/keys" {
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
			return
		}
		exchanges++
		_ = r.ParseForm()
		if r.Form.Get("code_verifier") != expectedVerifier || r.Form.Get("client_secret") != "synthetic-test-secret" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "unused", "token_type": "Bearer", "id_token": signedToken})
	}))
	t.Cleanup(server.Close)
	issuer := "https://login.microsoftonline.com/" + testEntraTenant + "/v2.0"
	service.oauth.Endpoint.TokenURL = server.URL + "/token"
	service.verifier = oidc.NewVerifier(issuer, oidc.NewRemoteKeySet(ctx, server.URL+"/keys"), &oidc.Config{ClientID: testEntraClient, SupportedSigningAlgs: []string{oidc.RS256}})
	for _, tc := range []struct {
		name    string
		reauth  bool
		mutate  func(map[string]any)
		denied  bool
		fresh   bool
		wantErr error
	}{
		{name: "verified SSO has no sudo"},
		{name: "fresh authentication", mutate: func(c map[string]any) { c["auth_time"] = time.Now().Unix() }, fresh: true},
		{name: "wrong audience", mutate: func(c map[string]any) { c["aud"] = "other" }, denied: true},
		{name: "wrong issuer", mutate: func(c map[string]any) { c["iss"] = "https://invalid.example" }, denied: true},
		{name: "wrong tenant", mutate: func(c map[string]any) { c["tid"] = testEntraClient }, denied: true},
		{name: "invalid object", mutate: func(c map[string]any) { c["oid"] = "user@example.test" }, denied: true},
		{name: "wrong nonce", mutate: func(c map[string]any) { c["nonce"] = "wrong" }, denied: true},
		{name: "expired", mutate: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, denied: true},
		{name: "future activation", mutate: func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, denied: true},
		{name: "missing role", mutate: func(c map[string]any) { delete(c, "roles") }, denied: true},
		{name: "sudo requires auth time", reauth: true, denied: true, wantErr: ErrEntraAuthTimeMissing},
		{
			name: "sudo rejects old auth time despite fresh iat", reauth: true, denied: true, wantErr: ErrEntraAuthTimeStale,
			mutate: func(c map[string]any) { c["auth_time"] = time.Now().Add(-5 * time.Minute).Unix() },
		},
		{
			name: "sudo rejects future auth time", reauth: true, denied: true, wantErr: ErrEntraAuthTimeStale,
			mutate: func(c map[string]any) { c["auth_time"] = time.Now().Add(5 * time.Minute).Unix() },
		},
		{
			name: "untrusted token cannot trigger configuration error", reauth: true, denied: true,
			mutate: func(c map[string]any) { c["nonce"] = "wrong" },
		},
		{
			name:   "ordinary SSO with old authentication is not sudo",
			mutate: func(c map[string]any) { c["auth_time"] = time.Now().Add(-time.Hour).Unix() },
		},
		{name: "sudo accepts fresh auth", reauth: true, mutate: func(c map[string]any) { c["auth_time"] = time.Now().Unix() }, fresh: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			username := ""
			if tc.reauth {
				username = "bound-user"
			}
			location, state, err := service.Start(ctx, "/roles", username)
			require.NoError(t, err)
			parsed, err := url.Parse(location)
			require.NoError(t, err)
			require.Equal(t, "S256", parsed.Query().Get("code_challenge_method"))
			require.NotEmpty(t, parsed.Query().Get("code_challenge"))
			if tc.reauth {
				require.Equal(t, "0", parsed.Query().Get("max_age"))
				require.Equal(t, "login", parsed.Query().Get("prompt"))
				require.JSONEq(t, `{"id_token":{"auth_time":{"essential":true}}}`, parsed.Query().Get("claims"))
			} else {
				require.Empty(t, parsed.Query().Get("claims"))
				require.Empty(t, parsed.Query().Get("prompt"))
			}
			var flow entraFlow
			data, err := cache.Get(ctx, "entra:flow:"+state).Bytes()
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(data, &flow))
			expectedVerifier = flow.Verifier
			claims := map[string]any{"iss": issuer, "aud": testEntraClient, "sub": "opaque-subject", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": flow.Nonce, "tid": testEntraTenant, "oid": "33333333-3333-3333-3333-333333333333", "preferred_username": "synthetic@example.test", "roles": []string{"Blocklist.Viewer"}}
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			payload, err := json.Marshal(claims)
			require.NoError(t, err)
			signed, err := signer.Sign(payload)
			require.NoError(t, err)
			signedToken, err = signed.CompactSerialize()
			require.NoError(t, err)
			before := exchanges
			_, err = service.Finish(ctx, state, strings.Repeat("x", 43), "code")
			require.ErrorIs(t, err, ErrEntraSignIn)
			require.Equal(t, before, exchanges)
			result, err := service.Finish(ctx, state, state, "code")
			if tc.denied {
				require.ErrorIs(t, err, ErrEntraSignIn)
				require.Nil(t, result)
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
				} else {
					require.NotErrorIs(t, err, ErrEntraAuthTimeMissing)
					require.NotErrorIs(t, err, ErrEntraAuthTimeStale)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, "viewer", result.Identity.RoleID)
				require.Equal(t, tc.fresh, result.HasFreshAuth)
				require.Equal(t, "/roles", result.Next)
			}
			_, err = service.Finish(ctx, state, state, "code")
			require.ErrorIs(t, err, ErrEntraSignIn)
			require.Equal(t, before+1, exchanges, "a replay must never exchange another code")
		})
	}
}
