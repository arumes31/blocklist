package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"blocklist/internal/config"
	"blocklist/internal/models"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

var entraUUID = regexp.MustCompile(`(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

var ErrEntraSignIn = errors.New("entra: sign-in could not be verified")

// These failures are classified only after signature and identity validation.
// They wrap ErrEntraSignIn so callers can still handle all sign-in denials alike.
var (
	ErrEntraAuthTimeMissing = fmt.Errorf("%w: missing authentication time", ErrEntraSignIn)
	ErrEntraAuthTimeStale   = fmt.Errorf("%w: authentication time is not fresh", ErrEntraSignIn)
)

func ValidEntraID(value string) bool {
	return entraUUID.MatchString(value)
}

type entraFlow struct {
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Next     string `json:"next"`
	Username string `json:"username"`
	Started  int64  `json:"started"`
}

type EntraResult struct {
	Identity     models.EntraIdentity
	Next         string
	Username     string
	HasFreshAuth bool
}

type EntraService struct {
	cfg      *config.Config
	redis    redis.Cmdable
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

func NewEntraService(cfg *config.Config, cache redis.Cmdable) (*EntraService, error) {
	if cfg == nil || !cfg.EntraEnabled {
		return nil, nil
	}
	if !entraUUID.MatchString(cfg.EntraTenantID) || !entraUUID.MatchString(cfg.EntraClientID) {
		return nil, errors.New("entra: tenant and client must be application registration uuid values")
	}
	redirect, err := url.Parse(cfg.EntraRedirectURL)
	if err != nil {
		return nil, errors.New("entra: invalid redirect url")
	}
	localHTTP := redirect.Scheme == "http" && (redirect.Hostname() == "localhost" || redirect.Hostname() == "127.0.0.1")
	validURL := redirect.Host != "" && redirect.User == nil && redirect.RawQuery == "" && redirect.Fragment == ""
	if !validURL || redirect.Path != "/auth/entra/callback" || (redirect.Scheme != "https" && !localHTTP) {
		return nil, errors.New("entra: redirect must use https (or local http) and /auth/entra/callback")
	}
	roles := []string{cfg.EntraViewerAppRole, cfg.EntraModeratorAppRole, cfg.EntraEditorAppRole}
	for i, role := range roles {
		if strings.TrimSpace(role) == "" || slices.Contains(roles[:i], role) {
			return nil, errors.New("entra: app role values must be nonempty and distinct")
		}
	}
	// The administrator supplies a mounted file, matching Hookwise's secret boundary.
	secret, err := os.ReadFile(cfg.EntraClientSecretFile)
	if err != nil || len(strings.TrimSpace(string(secret))) == 0 || len(secret) > 16384 {
		return nil, errors.New("entra: client secret file is unavailable or invalid")
	}
	if cache == nil {
		return nil, errors.New("entra: one-time flow storage is unavailable")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	tenant := strings.ToLower(cfg.EntraTenantID)
	authority := "https://login.microsoftonline.com/" + tenant
	keyContext := oidc.ClientContext(context.Background(), client)
	keys := oidc.NewRemoteKeySet(keyContext, authority+"/discovery/v2.0/keys")
	return &EntraService{
		cfg: cfg, redis: cache, client: client,
		oauth: oauth2.Config{
			ClientID: cfg.EntraClientID, ClientSecret: strings.TrimSpace(string(secret)),
			RedirectURL: cfg.EntraRedirectURL, Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL: authority + "/oauth2/v2.0/authorize", TokenURL: authority + "/oauth2/v2.0/token",
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		verifier: oidc.NewVerifier(authority+"/v2.0", keys, &oidc.Config{
			ClientID: cfg.EntraClientID, SupportedSigningAlgs: []string{oidc.RS256},
		}),
	}, nil
}

func randomEntraValue() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generating login challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (s *EntraService) Start(ctx context.Context, next, username string) (string, string, error) {
	state, err := randomEntraValue()
	if err != nil {
		return "", "", err
	}
	nonce, err := randomEntraValue()
	if err != nil {
		return "", "", err
	}
	flow := entraFlow{Nonce: nonce, Verifier: oauth2.GenerateVerifier(), Next: next, Username: username, Started: time.Now().Unix()}
	data, err := json.Marshal(flow)
	if err != nil {
		return "", "", fmt.Errorf("encoding login flow: %w", err)
	}
	if err := s.redis.Set(ctx, "entra:flow:"+state, data, 10*time.Minute).Err(); err != nil {
		return "", "", fmt.Errorf("saving login flow: %w", err)
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(flow.Verifier), oauth2.SetAuthURLParam("response_mode", "query")}
	if username != "" {
		opts = append(opts,
			oauth2.SetAuthURLParam("prompt", "login"),
			oauth2.SetAuthURLParam("max_age", "0"),
			oauth2.SetAuthURLParam("claims", `{"id_token":{"auth_time":{"essential":true}}}`),
		)
	}
	return s.oauth.AuthCodeURL(state, opts...), state, nil
}

func (s *EntraService) Finish(ctx context.Context, state, cookie, code string) (*EntraResult, error) {
	validState := len(state) == 43 && len(cookie) == 43 && subtle.ConstantTimeCompare([]byte(state), []byte(cookie)) == 1
	if !validState {
		return nil, ErrEntraSignIn
	}
	// GETDEL consumes the challenge atomically, even across concurrent callbacks.
	data, err := s.redis.GetDel(ctx, "entra:flow:"+state).Bytes()
	if err != nil {
		return nil, ErrEntraSignIn
	}
	var flow entraFlow
	if err := json.Unmarshal(data, &flow); err != nil {
		return nil, ErrEntraSignIn
	}
	if code == "" || len(code) > 16384 || time.Now().Unix()-flow.Started > 600 {
		return nil, ErrEntraSignIn
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.client)
	token, err := s.oauth.Exchange(ctx, code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		return nil, ErrEntraSignIn // Never return provider bodies or credentials to logs.
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, ErrEntraSignIn
	}
	verified, err := s.verifier.Verify(ctx, raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(flow.Nonce)) != 1 {
		return nil, ErrEntraSignIn
	}
	var claims struct {
		TenantID  string   `json:"tid"`
		ObjectID  string   `json:"oid"`
		UPN       string   `json:"preferred_username"`
		Roles     []string `json:"roles"`
		NotBefore int64    `json:"nbf"`
		AuthTime  int64    `json:"auth_time"`
	}
	if err := verified.Claims(&claims); err != nil {
		return nil, ErrEntraSignIn
	}
	validIdentity := strings.EqualFold(claims.TenantID, s.cfg.EntraTenantID) && entraUUID.MatchString(claims.ObjectID)
	validTime := claims.NotBefore <= time.Now().Unix()+60 && verified.IssuedAt.Before(time.Now().Add(time.Minute))
	if !validIdentity || !validTime || len(claims.UPN) > 255 {
		return nil, ErrEntraSignIn
	}
	if flow.Username != "" {
		if claims.AuthTime == 0 {
			return nil, ErrEntraAuthTimeMissing
		}
		if claims.AuthTime < flow.Started-60 || claims.AuthTime > time.Now().Unix()+60 {
			return nil, ErrEntraAuthTimeStale
		}
	}
	role := s.MapRole(claims.Roles)
	if role == "" {
		return nil, ErrEntraSignIn
	}
	return &EntraResult{
		Identity: models.EntraIdentity{TenantID: strings.ToLower(claims.TenantID), ObjectID: strings.ToLower(claims.ObjectID), UPN: claims.UPN, RoleID: role},
		Next:     flow.Next, Username: flow.Username,
		HasFreshAuth: claims.AuthTime >= flow.Started-60 && claims.AuthTime <= time.Now().Unix()+60,
	}, nil
}

func (s *EntraService) MapRole(claims []string) string {
	for _, mapping := range []struct{ claim, role string }{
		{claim: s.cfg.EntraEditorAppRole, role: "editor"},
		{claim: s.cfg.EntraModeratorAppRole, role: "moderator"},
		{claim: s.cfg.EntraViewerAppRole, role: "viewer"},
	} {
		if mapping.claim != "" && slices.Contains(claims, mapping.claim) {
			return mapping.role
		}
	}
	return ""
}
