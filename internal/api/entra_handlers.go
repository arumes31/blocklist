package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"blocklist/internal/service"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	gorillasessions "github.com/gorilla/sessions"
	zlog "github.com/rs/zerolog/log"
)

const entraFlowCookie = "blocklist_entra_flow"

type entraFlowProvider interface {
	Start(context.Context, string, string) (string, string, error)
	Finish(context.Context, string, string, string) (*service.EntraResult, error)
}

func (h *APIHandler) EntraLogin(c *gin.Context) {
	if h.entraService == nil || h.identityRepo == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	next := c.DefaultQuery("next", "/dashboard")
	if !h.isValidRedirect(next) {
		next = "/dashboard"
	}
	username := ""
	if c.Query("reauth") == "1" {
		session := sessions.Default(c)
		if session.Get("logged_in") != true || session.Get("auth_source") != "entra" {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		username, _ = session.Get("username").(string)
		if username == "" {
			c.Redirect(http.StatusFound, "/login")
			return
		}
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	location, state, err := h.entraService.Start(ctx, next, username)
	if err != nil {
		h.entraFailure(c)
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(entraFlowCookie, state, 600, "/auth/entra", "", h.cfg.CookieSecure || h.cfg.ForceHTTPS, true)
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, location)
}

func (h *APIHandler) EntraCallback(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	if h.entraService == nil || h.identityRepo == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	cookie, err := c.Cookie(entraFlowCookie)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(entraFlowCookie, "", -1, "/auth/entra", "", h.cfg.CookieSecure || h.cfg.ForceHTTPS, true)
	if err != nil {
		h.entraFailure(c)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	result, err := h.entraService.Finish(ctx, c.Query("state"), cookie, c.Query("code"))
	if err != nil {
		h.entraVerificationFailure(c, err)
		return
	}
	// A sudo flow must return the same immutable identity, not merely another
	// authenticated Microsoft account with similar permissions.
	if result.Username != "" {
		current, err := h.pgRepo.GetAdmin(result.Username)
		if err != nil || current == nil || current.Disabled || current.EntraTenantID == nil || current.EntraObjectID == nil {
			h.entraFailure(c)
			return
		}
		if !strings.EqualFold(*current.EntraTenantID, result.Identity.TenantID) || !strings.EqualFold(*current.EntraObjectID, result.Identity.ObjectID) {
			h.entraFailure(c)
			return
		}
	}
	admin, err := h.identityRepo.SignInEntra(ctx, result.Identity, h.cfg.EntraAutoProvision)
	if err != nil || admin == nil || admin.Disabled || admin.Username == h.cfg.GUIAdmin {
		h.entraFailure(c)
		return
	}
	session := sessions.Default(c)
	// Clear the old server-side session and request a fresh session identifier.
	rawSession, ok := session.(interface {
		Session() *gorillasessions.Session
	})
	if !ok {
		h.entraFailure(c)
		return
	}
	old := rawSession.Session()
	options := *old.Options
	expired := options
	expired.MaxAge = -1
	old.Options = &expired
	session.Delete("session_rotation") // Mark the session dirty so Save deletes it.
	if err := session.Save(); err != nil {
		h.entraFailure(c)
		return
	}
	old.ID = ""
	old.Options = &options
	session.Clear()
	session.Set("logged_in", true)
	session.Set("username", admin.Username)
	session.Set("auth_source", "entra")
	session.Set("client_ip", c.ClientIP())
	session.Set("login_time", time.Now().UTC().Format(time.RFC3339))
	if result.HasFreshAuth {
		session.Set("sudo_time", time.Now().Unix())
	}
	session.Set("role", admin.Role)
	session.Set("permissions", admin.Permissions)
	session.Set("session_version", admin.SessionVersion)
	if err := session.Save(); err != nil {
		h.entraFailure(c)
		return
	}
	if !h.isValidRedirect(result.Next) {
		result.Next = "/dashboard"
	}
	c.Redirect(http.StatusFound, result.Next)
}

func (h *APIHandler) entraFailure(c *gin.Context) {
	h.entraVerificationFailure(c, service.ErrEntraSignIn)
}

func (h *APIHandler) entraVerificationFailure(c *gin.Context, failure error) {
	message := "Microsoft sign-in could not be verified. Try again or contact an administrator."
	reason := "Sign-in could not be verified"
	data := gin.H{}
	switch {
	case errors.Is(failure, service.ErrEntraAuthTimeMissing):
		message = "Microsoft did not provide the authentication time needed to verify your identity. " +
			"Ask an administrator to add the auth_time optional claim to ID tokens in the Blocklist Entra app registration, then verify again."
		reason = "Reauthentication denied: auth_time_missing; configure the ID token optional claim"
	case errors.Is(failure, service.ErrEntraAuthTimeStale):
		message = "Microsoft did not confirm a fresh sign-in. Start identity verification again and sign in with the same account. " +
			"If this continues, ask an administrator to check the server clock and Entra sign-in policy."
		reason = "Reauthentication denied: auth_time_not_fresh"
	}
	if errors.Is(failure, service.ErrEntraAuthTimeMissing) || errors.Is(failure, service.ErrEntraAuthTimeStale) {
		// Retrying ordinary SSO would lose the sensitive-action verification flow.
		data["is_sudo"] = true
		data["entra_sudo"] = true
		data["next"] = "/admin_management"
	}
	if h.pgRepo != nil {
		if err := h.pgRepo.LogAction("system", "ENTRA_LOGIN_FAILURE", "REDACTED", reason); err != nil {
			zlog.Error().Err(err).Msg("Failed to record Entra sign-in denial")
		}
	}
	data["error"] = message
	h.renderHTML(c, http.StatusUnauthorized, "login.html", data)
}
