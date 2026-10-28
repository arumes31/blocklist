package api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"blocklist/internal/models"
	"blocklist/internal/service"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	gorillasessions "github.com/gorilla/sessions"
	"github.com/pquerna/otp/totp"
	zlog "github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

func (h *APIHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for Bearer token first
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			c.Set("token_auth", true)
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			// In test mode with no DB, allow a special test token
			if gin.Mode() == gin.TestMode && h.pgRepo == nil && tokenStr == "test-token" {
				c.Set("username", "admin")
				c.Set("role", "admin")
				c.Set("permissions", "block_ips,unblock_ips,whitelist_ips")
				c.Next()
				return
			}

			if h.pgRepo != nil {
				// Hash the presented token
				hash := sha256.Sum256([]byte(tokenStr))
				hashStr := hex.EncodeToString(hash[:])

				token, err := h.pgRepo.GetAPITokenByHash(hashStr)
				if err == nil && token != nil {
					// Check expiration
					if token.ExpiresAt != nil {
						expiresAt, err := time.Parse(time.RFC3339, *token.ExpiresAt)
						if err != nil {
							zlog.Error().Err(err).Str("token", token.Name).Msg("Failed to parse token expiration, treating as expired")
							c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token expiration format"})
							c.Abort()
							return
						}
						if time.Now().After(expiresAt) {
							c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
							c.Abort()
							return
						}
					}

					// Check IP restrictions
					if !h.isIPInCIDRs(c.ClientIP(), token.AllowedIPs) {
						zlog.Warn().
							Str("token", token.Name).
							Msg("API Token used from unauthorized IP")
						c.JSON(http.StatusForbidden, gin.H{"error": "Token not allowed"})
						c.Abort()
						return
					}

					owner, err := h.pgRepo.GetAdmin(token.Username)
					if err != nil || owner == nil || owner.Disabled {
						c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token owner is unavailable"})
						return
					}
					if err := h.pgRepo.UpdateTokenLastUsed(token.ID, c.ClientIP()); err != nil {
						zlog.Error().Err(err).Int("token_id", token.ID).Msg("Failed to update token last_used")
					}
					permissions := token.Permissions
					if h.identityRepo != nil {
						ownerPermissions := owner.Permissions
						if owner.Username == h.cfg.GUIAdmin {
							ownerPermissions = models.AllPermissions()
						}
						permissions = models.IntersectPermissions(permissions, ownerPermissions)
					}
					c.Set("username", token.Username)
					c.Set("role", token.Role)
					c.Set("permissions", permissions)
					c.Next()
					return
				}
			}
			// An unrecognised Bearer token never falls back to the session
			// cookie: CSRF checks are skipped for Bearer requests, so a
			// fallback would let a forged header ride an ambient session.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Legacy Basic Auth fallback: opt-in (ALLOW_BASIC_AUTH) and restricted to
		// the whitelist read endpoints. It bypasses TOTP, so BasicAuthLimiter
		// throttles attempts before the bcrypt compare runs.
		username, password, ok := c.Request.BasicAuth()
		if ok && h.basicAuthAllowed(c) {
			admin, err := h.pgRepo.GetAdmin(username)
			if err == nil && admin != nil && admin.Disabled {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				return
			}
			if err == nil && admin != nil && !admin.Disabled && admin.AuthSource != "entra" {
				if bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)) == nil {
					c.Set("username", username)
					c.Set("role", admin.Role)
					c.Set("permissions", admin.Permissions)
					c.Next()
					return
				}
			}
			zlog.Warn().Str("username", username).Str("ip", c.ClientIP()).Msg("Failed Basic authentication attempt")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		session := sessions.Default(c)

		// If session is invalid (e.g. key mismatch after restart), clear it
		if loggedIn := session.Get("logged_in"); loggedIn == nil {
			zlog.Debug().Str("path", c.Request.URL.Path).Msg("Session missing or invalid")

			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			} else {
				// Clear any potentially corrupt cookies by clearing session
				session.Clear()
				if err := session.Save(); err != nil {
					zlog.Error().Err(err).Msg("Failed to clear corrupt session")
				}
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}
		clientIP := c.ClientIP()
		if storedIP := session.Get("client_ip"); storedIP == nil || storedIP.(string) != clientIP {
			session.Clear()
			_ = session.Save()
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		usernameSess, ok := session.Get("username").(string)
		if !ok || usernameSess == "" || h.sessionIdleExpired(session) {
			session.Clear()
			_ = session.Save()
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		username = usernameSess

		// Verify user still exists in database
		admin, err := h.pgRepo.GetAdmin(username)
		if err != nil || admin == nil || admin.Disabled {
			zlog.Warn().Str("username", username).Msg("Session account unavailable")
			session.Clear()
			_ = session.Save()
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		c.Set("username", username)

		// Resolve from the primary database on every request; role revocation
		// must not wait for a session cache or a read replica to catch up.
		permissions := models.WorkspacePermissions(*admin)
		if username == h.cfg.GUIAdmin {
			permissions = models.AllPermissions()
		}
		c.Set("role", admin.Role)
		c.Set("permissions", permissions)
		c.Set("auth_source", admin.AuthSource)
		c.Set("display_username", admin.DisplayName())
		if h.identityRepo != nil && !models.HasPermission(permissions, "gui_read") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "This account does not have workspace access."})
			return
		}

		c.Next()
	}
}

// SessionMaxAge is the absolute lifetime of a browser session, counted from
// sign-in no matter how active the session is.
const SessionMaxAge = 7 * 24 * time.Hour

// sessionIdleExpired reports whether the session is past SessionMaxAge since
// sign-in or has been unused for longer than SESSION_IDLE_MINUTES, and
// otherwise records this request as activity.
// The timestamp is rewritten at most once a minute to limit session writes.
func (h *APIHandler) sessionIdleExpired(session sessions.Session) bool {
	// Activity saves refresh the cookie and store TTL, so the absolute lifetime
	// is enforced from the immutable sign-in time instead.
	if loginTime, ok := session.Get("login_time").(string); ok {
		if signedIn, err := time.Parse(time.RFC3339, loginTime); err != nil || time.Since(signedIn) > SessionMaxAge {
			return true
		}
	}
	if h.cfg == nil || h.cfg.SessionIdleMinutes <= 0 {
		return false
	}
	now := time.Now().Unix()
	last, ok := session.Get("last_seen").(int64)
	if ok && now-last > int64(h.cfg.SessionIdleMinutes)*60 {
		return true
	}
	if !ok || now-last >= 60 {
		session.Set("last_seen", now)
		if err := session.Save(); err != nil {
			zlog.Error().Err(err).Msg("Failed to record session activity")
		}
	}
	return false
}

// basicAuthAllowed reports whether a Basic credential may be checked for this request.
func (h *APIHandler) basicAuthAllowed(c *gin.Context) bool {
	if h.cfg == nil || !h.cfg.AllowBasicAuth || h.pgRepo == nil {
		return false
	}
	return c.Request.URL.Path == "/api/v1/whitelists" || c.Request.URL.Path == "/api/v1/whitelists-raw"
}

// BasicAuthLimiter applies the login rate limit to Basic credentials before
// AuthMiddleware spends a bcrypt compare on them.
func (h *APIHandler) BasicAuthLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h.loginLimiter != nil && strings.HasPrefix(c.GetHeader("Authorization"), "Basic ") && h.basicAuthAllowed(c) {
			h.loginLimiter(c) // calls c.Next() itself, or aborts with 429
			return
		}
		c.Next()
	}
}

func (h *APIHandler) RBACMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Role not found"})
			c.Abort()
			return
		}

		roleStr := role.(string)

		// admin > operator > viewer
		weights := map[string]int{"viewer": 1, "operator": 2, "admin": 3}
		if weights[roleStr] < weights[requiredRole] {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (h *APIHandler) SessionCheckMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		username := session.Get("username")
		if username == nil {
			c.Next()
			return
		}

		sVersion := session.Get("session_version")
		if sVersion == nil {
			// Old session, force logout
			session.Clear()
			_ = session.Save()
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		admin, err := h.pgRepo.GetAdmin(username.(string))
		if err != nil || admin == nil || admin.Disabled {
			session.Clear()
			_ = session.Save()
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		if admin.SessionVersion > sVersion.(int) {
			zlog.Info().Str("username", admin.Username).Msg("Session version mismatch, forcing logout")
			session.Clear()
			_ = session.Save()
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		c.Next()
	}
}

func (h *APIHandler) PermissionMiddleware(requiredPerms ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(requiredPerms) == 0 {
			c.Next()
			return
		}

		perms, exists := c.Get("permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permissions not found"})
			c.Abort()
			return
		}

		permStr := perms.(string)

		// Never promote a limited API token merely because its owner is GUIAdmin.
		username, _ := c.Get("username")
		if h.cfg != nil && username == h.cfg.GUIAdmin && !c.GetBool("token_auth") {
			// To match previous logic, admin bypasses everything except whitelist_ips restriction
			bypass := true
			for _, rp := range requiredPerms {
				if rp == "whitelist_ips" {
					bypass = false
					break
				}
			}

			if bypass {
				c.Next()
				return
			}
		}

		userPerms := strings.Split(permStr, ",")
		hasPerm := false
		for _, p := range userPerms {
			p = strings.TrimSpace(p)
			for _, rp := range requiredPerms {
				if p == rp {
					hasPerm = true
					break
				}
			}
			if hasPerm {
				break
			}
		}

		if !hasPerm {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient granular permissions"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (h *APIHandler) MetricsAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		allowedIPs := strings.Split(h.cfg.MetricsAllowedIPs, ",")
		clientIP := c.ClientIP()

		isAllowed := false
		for _, ip := range allowedIPs {
			if strings.TrimSpace(ip) == clientIP {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}
		c.Next()
	}
}

func (h *APIHandler) AdminOnlyMiddleware() gin.HandlerFunc {
	return h.PermissionMiddleware("manage_admins")
}

func (h *APIHandler) ShowLogin(c *gin.Context) {
	session := sessions.Default(c)
	if loggedIn := session.Get("logged_in"); loggedIn != nil && loggedIn.(bool) {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}
	h.renderHTML(c, http.StatusOK, "login.html", nil)
}

// defaultQRLogoPath is the location of the logo overlaid on generated QR codes.
const defaultQRLogoPath = "cmd/server/static/cd/favicon-color.png"

func (h *APIHandler) generateQRWithLogo(url string) ([]byte, error) {
	return h.generateQRWithLogoFromPath(url, defaultQRLogoPath)
}

func (h *APIHandler) generateQRWithLogoFromPath(url, logoPath string) ([]byte, error) {
	// Generate QR code with High error correction
	qr, err := qrcode.New(url, qrcode.High)
	if err != nil {
		return nil, err
	}

	// Create image from QR code
	img := qr.Image(256)

	// Try to load logo. logoPath is not attacker-controlled: production callers
	// pass the defaultQRLogoPath constant; only tests supply an alternate path.
	logoFile, err := os.Open(logoPath) // #nosec G304
	if err != nil {
		// Fallback to plain QR if logo not found
		return qr.PNG(256)
	}
	defer func() { _ = logoFile.Close() }()

	logoImg, _, err := image.Decode(logoFile)
	if err != nil {
		return qr.PNG(256)
	}

	// Prepare overlay
	canvas := image.NewRGBA(img.Bounds())
	draw.Draw(canvas, img.Bounds(), img, image.Point{}, draw.Src)

	// Calculate position (center)
	logoBounds := logoImg.Bounds()
	center := 256 / 2
	x0 := center - (logoBounds.Dx() / 2)
	y0 := center - (logoBounds.Dy() / 2)

	// Draw logo
	draw.Draw(canvas, logoBounds.Add(image.Pt(x0, y0)), logoImg, image.Point{}, draw.Over)

	// Encode back to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		return qr.PNG(256)
	}

	return buf.Bytes(), nil
}

// pendingEnrollmentTTL bounds how long a verified password may wait for the
// TOTP setup step.
const pendingEnrollmentTTL = 10 * time.Minute

// pendingEnrollmentCurrent reports whether the session's first-factor proof
// was issued recently and against the account's current credential version.
// A password, TOTP or status change bumps session_version and voids it.
func pendingEnrollmentCurrent(session sessions.Session, admin *models.AdminAccount) bool {
	version, okVersion := session.Get("pending_auth_version").(int)
	issued, okTime := session.Get("pending_auth_time").(int64)
	if !okVersion || !okTime || admin == nil || version != admin.SessionVersion {
		return false
	}
	age := time.Since(time.Unix(issued, 0))
	return age >= -time.Minute && age <= pendingEnrollmentTTL
}

// dummyBcryptHash is a valid cost-14 bcrypt hash of a fixed throwaway string.
// It is compared against during failed logins for unknown usernames so the
// timing matches a real (wrong-password) comparison, mitigating user enumeration.
const dummyBcryptHash = "$2a$14$8SoUqALkURy/rkPRGnG8e.yDiNLVzjktsOA/SnEv7041dyo3nhaT6"

func (h *APIHandler) VerifyFirstFactor(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if len(username) > 255 || len(password) > 2048 {
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "Invalid input length"})
		return
	}

	if h.cfg.DisableGUIAdminLogin && username == h.cfg.GUIAdmin {
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "GUIAdmin login is disabled"})
		return
	}

	admin, err := h.pgRepo.GetAdmin(username)
	if err != nil || admin == nil || admin.Disabled || admin.AuthSource == "entra" {
		// Run a dummy bcrypt comparison (same cost as real hashes) so the
		// response time for unknown usernames matches that of a wrong password,
		// preventing username enumeration via timing.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password))
		_ = h.pgRepo.LogAction("system", "LOGIN_FAILURE", "REDACTED", "Invalid Operator ID (Enumeration Protection)")
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
	if err != nil {
		_ = h.pgRepo.LogAction(username, "LOGIN_FAILURE", "REDACTED", "Invalid Password (Enumeration Protection)")
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if TOTP is setup
	if admin.Token == "" {
		// Generate temporary TOTP secret for setup
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Blocklist App",
			AccountName: username,
		})
		if err != nil {
			zlog.Error().Err(err).Msg("Failed to generate TOTP secret")
			h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "Internal error generating 2FA"})
			return
		}

		pngData, err := h.generateQRWithLogo(key.URL())
		if err != nil {
			zlog.Error().Err(err).Msg("Failed to generate QR with logo")
			// Fallback to simple QR
			simplePng, err2 := qrcode.Encode(key.URL(), qrcode.Medium, 256)
			if err2 != nil {
				zlog.Error().Err(err2).Msg("Failed to encode simple QR")
				h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "Internal error generating QR code"})
				return
			}
			pngData = simplePng
		}
		imgBase64 := base64.StdEncoding.EncodeToString(pngData)

		session := sessions.Default(c)
		session.Set("pending_auth_user", username)
		session.Set("pending_auth_verified", true)
		session.Set("pending_totp_secret", key.Secret())
		// Bind the password proof to this credential version and a short window
		// so a password reset (or time) revokes an unfinished enrollment.
		session.Set("pending_auth_version", admin.SessionVersion)
		session.Set("pending_auth_time", time.Now().Unix())
		if err := session.Save(); err != nil {
			zlog.Error().Err(err).Msg("Failed to save session for TOTP setup")
		}

		h.renderHTML(c, http.StatusOK, "login_totp_setup_step.html", gin.H{
			"username": username,
			"qr_image": "data:image/png;base64," + imgBase64,
			"secret":   key.Secret(),
		})
		return
	}

	// Success: Return TOTP field via HTMX
	session := sessions.Default(c)
	session.Set("pending_auth_user", username)
	session.Set("pending_auth_verified", true)
	if err := session.Save(); err != nil {
		zlog.Error().Err(err).Msg("Failed to save session for TOTP step")
	}

	h.renderHTML(c, http.StatusOK, "login_totp_step.html", gin.H{
		"username": username,
	})
}

func (h *APIHandler) Login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	totpCode := c.PostForm("totp")
	setupSecret := c.PostForm("setup_secret")

	if len(username) > 255 || len(password) > 2048 || len(totpCode) > 255 || len(setupSecret) > 2048 {
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "Invalid input length"})
		return
	}

	if h.cfg.DisableGUIAdminLogin && username == h.cfg.GUIAdmin {
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "GUIAdmin login is disabled"})
		return
	}

	session := sessions.Default(c)

	// Check for pending auth session if password is not provided (multi-step)
	isMultiStep := false
	if password == "" {
		pendingUser, hasPendingUser := session.Get("pending_auth_user").(string)
		pendingVerified, hasPendingVerification := session.Get("pending_auth_verified").(bool)
		if !hasPendingUser || pendingUser != username || !hasPendingVerification || !pendingVerified {
			zlog.Warn().Str("username", username).Msg("Invalid multi-step login attempt")
			_ = h.pgRepo.LogAction(username, "LOGIN_FAILURE", c.ClientIP(), "Invalid multi-step session or mismatch")
			h.renderHTML(c, http.StatusOK, "login.html", gin.H{
				"error": "Session expired or invalid login attempt. Please restart login.",
			})
			return
		}
		isMultiStep = true
	}

	// If it's a setup attempt
	if setupSecret != "" {
		pendingUser, hasPendingUser := session.Get("pending_auth_user").(string)
		pendingVerified, hasPendingVerification := session.Get("pending_auth_verified").(bool)
		pendingSecret, hasPendingSecret := session.Get("pending_totp_secret").(string)
		if !hasPendingUser || pendingUser != username || !hasPendingVerification || !pendingVerified || !hasPendingSecret || pendingSecret != setupSecret {
			zlog.Warn().Str("username", username).Msg("Unauthenticated or invalid TOTP setup attempt")
			_ = h.pgRepo.LogAction(username, "LOGIN_FAILURE", c.ClientIP(), "Unauthenticated TOTP setup attempt")
			h.renderHTML(c, http.StatusOK, "login.html", gin.H{
				"error":    "Session expired or invalid setup attempt.",
				"username": username,
			})
			return
		}

		admin, _ := h.pgRepo.GetAdmin(username)

		// Prevent overwriting existing token via this flow
		if admin == nil || admin.Disabled || admin.AuthSource == "entra" {
			h.renderHTML(c, http.StatusUnauthorized, "login.html", gin.H{"error": "Restart sign-in using this account's configured authentication method."})
			return
		}
		if admin != nil && admin.Token != "" {
			zlog.Warn().Str("username", username).Msg("Attempt to overwrite existing TOTP token")
			_ = h.pgRepo.LogAction(username, "SECURITY_WARNING", c.ClientIP(), "Attempt to overwrite existing TOTP token")
			h.renderHTML(c, http.StatusOK, "login.html", gin.H{
				"error":    "2FA is already configured for this account.",
				"username": username,
			})
			return
		}

		if !pendingEnrollmentCurrent(session, admin) {
			zlog.Warn().Str("username", username).Msg("Stale TOTP enrollment proof rejected")
			_ = h.pgRepo.LogAction(username, "LOGIN_FAILURE", c.ClientIP(), "Stale TOTP enrollment session")
			session.Delete("pending_auth_user")
			session.Delete("pending_auth_verified")
			session.Delete("pending_totp_secret")
			session.Delete("pending_auth_version")
			session.Delete("pending_auth_time")
			_ = session.Save()
			h.renderHTML(c, http.StatusOK, "login.html", gin.H{
				"error":    "Session expired or invalid setup attempt.",
				"username": username,
			})
			return
		}

		if h.validateTOTPOnce(username, totpCode, setupSecret) {
			// Save the secret only if the account is still at the credential
			// version the password proof was issued for (checked atomically).
			if err := h.pgRepo.EnrollAdminToken(username, setupSecret, admin.SessionVersion); err != nil {
				zlog.Error().Err(err).Msg("Failed to complete authenticator enrollment")
				h.renderHTML(c, http.StatusUnauthorized, "login.html", gin.H{"error": "Sign-in could not be completed. Please restart sign-in."})
				return
			}
			_ = h.pgRepo.LogAction(username, "TOTP_SETUP", c.ClientIP(), "Successful 2FA setup")
			// Clear setup secret from session immediately
			session.Delete("pending_totp_secret")
			_ = session.Save()
		} else {
			_ = h.pgRepo.LogAction(username, "LOGIN_FAILURE", c.ClientIP(), "Invalid TOTP during setup")
			h.renderHTML(c, http.StatusOK, "login.html", gin.H{
				"error":    "Invalid TOTP code during setup. Please try again.",
				"username": username,
			})
			return
		}
	}

	authenticated := false
	switch {
	case setupSecret != "":
		// Reaching here with setupSecret set means the setup block above already
		// validated totpCode against setupSecret and persisted the token, so the
		// user is authenticated. Avoid re-validating via VerifyTOTP, which reads
		// the (possibly lagging) replica and now fails-closed on an empty token.
		authenticated = true
	case isMultiStep:
		authenticated = h.authService.VerifyTOTP(username, totpCode)
	default:
		authenticated = h.authService.CheckAuth(username, password, totpCode)
	}

	if authenticated {
		admin, err := h.pgRepo.GetAdmin(username)
		if err != nil || admin == nil || admin.Disabled {
			session.Clear()
			if err := session.Save(); err != nil {
				zlog.Error().Err(err).Msg("Failed to clear rejected sign-in session")
			}
			h.renderHTML(c, http.StatusUnauthorized, "login.html", gin.H{"error": "Sign-in could not be completed. Please restart sign-in."})
			return
		}
		// A fresh session identifier prevents fixation of a pre-login session.
		if err := rotateSession(session); err != nil {
			zlog.Error().Err(err).Msg("Failed to rotate session during login")
			h.renderHTML(c, http.StatusUnauthorized, "login.html", gin.H{"error": "Sign-in could not be completed. Please restart sign-in."})
			return
		}
		session.Set("logged_in", true)
		session.Set("username", username)
		session.Set("auth_source", "local")
		session.Set("client_ip", c.ClientIP())
		session.Set("login_time", time.Now().UTC().Format(time.RFC3339))
		session.Set("sudo_time", time.Now().Unix()) // Initial sudo mode
		session.Set("role", admin.Role)
		session.Set("permissions", admin.Permissions)
		session.Set("session_version", admin.SessionVersion)
		if err := session.Save(); err != nil {
			zlog.Error().Err(err).Msg("Failed to save session during login")
		}

		_ = h.pgRepo.LogAction(username, "LOGIN_SUCCESS", "REDACTED", "")

		c.Redirect(http.StatusFound, "/dashboard")
		return
	}

	// On failed login, clear pending state to be safe
	session.Delete("pending_auth_user")
	session.Delete("pending_auth_verified")
	session.Delete("pending_totp_secret")
	session.Delete("pending_auth_version")
	session.Delete("pending_auth_time")
	_ = session.Save()

	_ = h.pgRepo.LogAction(username, "LOGIN_FAILURE", "REDACTED", "Invalid TOTP or Credentials")

	h.renderHTML(c, http.StatusOK, "login.html", gin.H{
		"error":    "Invalid credentials or TOTP code",
		"username": username,
		"step":     "totp",
	})
}

// validateTOTPOnce checks a TOTP code and rejects reuse of an accepted time step.
func (h *APIHandler) validateTOTPOnce(username, code, secret string) bool {
	claimer, _ := h.redisRepo.(service.TOTPStepClaimer)
	return service.ValidateTOTPOnce(claimer, username, code, secret)
}

// rotateSession deletes the current server-side session and clears its values,
// so the next Save issues a new session identifier.
func rotateSession(session sessions.Session) error {
	rawSession, ok := session.(interface {
		Session() *gorillasessions.Session
	})
	if !ok {
		return fmt.Errorf("session store does not support rotation")
	}
	old := rawSession.Session()
	options := *old.Options
	expired := options
	expired.MaxAge = -1
	old.Options = &expired
	session.Delete("session_rotation") // Mark the session dirty so Save deletes it.
	if err := session.Save(); err != nil {
		return err
	}
	old.ID = ""
	old.Options = &options
	session.Clear()
	return nil
}

func (h *APIHandler) SudoMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetBool("token_auth") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Use an authenticated browser session for this sensitive action."})
			return
		}
		session := sessions.Default(c)
		sudoTime := session.Get("sudo_time")

		isFresh := false
		if sudoTime != nil {
			ts := sudoTime.(int64)
			if time.Now().Unix()-ts < 300 { // 5 minutes
				isFresh = true
			}
		}

		if !isFresh {
			if strings.Contains(c.GetHeader("Accept"), "application/json") {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Verify your identity before making this change.", "reauth_url": "/sudo?next=/admin_management"})
				return
			}
			if c.GetHeader("HX-Request") != "" {
				// For HTMX, trigger a modal or redirect
				c.Header("HX-Trigger", "openSudoModal")
				c.AbortWithStatus(http.StatusForbidden)
			} else {
				// Standard redirect
				c.Redirect(http.StatusFound, "/sudo?next="+c.Request.URL.Path)
				c.Abort()
			}
			return
		}
		c.Next()
	}
}

func (h *APIHandler) ShowSudo(c *gin.Context) {
	next := c.Query("next")
	if !h.isValidRedirect(next) {
		next = "/dashboard"
	}
	h.renderHTML(c, http.StatusOK, "login.html", gin.H{"step": "totp", "is_sudo": true, "entra_sudo": c.GetString("auth_source") == "entra", "next": next, "username": c.GetString("username")})
}

func (h *APIHandler) VerifySudo(c *gin.Context) {
	session := sessions.Default(c)
	username, ok := session.Get("username").(string)
	if !ok || username == "" || c.GetBool("token_auth") {
		// Sudo is a browser-session concept; API tokens and session-less
		// callers cannot elevate.
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	totpCode := c.PostForm("totp")
	next := c.PostForm("next")
	if next == "" {
		next = c.Query("next")
	}

	if len(totpCode) > 255 || len(next) > 2048 {
		h.renderHTML(c, http.StatusOK, "login.html", gin.H{"error": "Invalid input length", "step": "totp", "is_sudo": true, "next": "/dashboard"})
		return
	}

	admin, _ := h.pgRepo.GetAdmin(username)
	// admin.Token must be non-empty: an empty secret would accept the
	// attacker-computable empty-key code, allowing sudo elevation without 2FA.
	if admin != nil && !admin.Disabled && admin.Token != "" && h.validateTOTPOnce(username, totpCode, admin.Token) {
		session.Set("sudo_time", time.Now().Unix())
		_ = session.Save()

		if !h.isValidRedirect(next) {
			next = "/dashboard"
		}
		c.Redirect(http.StatusFound, next)
		return
	}

	h.renderHTML(c, http.StatusOK, "login.html", gin.H{
		"error":   "Invalid TOTP code",
		"step":    "totp",
		"is_sudo": true,
		"next":    next,
	})
}

func (h *APIHandler) Logout(c *gin.Context) {
	// Sign-out stays a plain link, but a GET navigation started by another
	// site (Sec-Fetch-Site: cross-site) must not end the user's session.
	if c.Request.Method == http.MethodGet && c.GetHeader("Sec-Fetch-Site") == "cross-site" {
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}
	session := sessions.Default(c)
	session.Clear()
	_ = session.Save()
	c.Redirect(http.StatusFound, "/login")
}

func (h *APIHandler) validatePermissionSubset(requestedPerms, userPerms string) (string, error) {
	if requestedPerms == "" {
		return "", nil
	}

	rPerms := strings.Split(requestedPerms, ",")
	uPerms := strings.Split(userPerms, ",")
	validPerms := []string{}

	for _, rp := range rPerms {
		rp = strings.TrimSpace(rp)
		if rp == "" {
			continue
		}
		found := false
		for _, up := range uPerms {
			if rp == strings.TrimSpace(up) {
				validPerms = append(validPerms, rp)
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("insufficient permissions to grant: %s", rp)
		}
	}
	return strings.Join(validPerms, ","), nil
}

// rejectTokenIssuedByToken stops an API token from issuing or widening tokens.
// Otherwise a token restricted by allowed_ips could mint an unrestricted
// sibling for the same owner and escape its network binding.
func rejectTokenIssuedByToken(c *gin.Context) bool {
	if !c.GetBool("token_auth") {
		return false
	}
	c.String(http.StatusForbidden, "API tokens cannot create or modify API tokens; sign in to the workspace")
	return true
}

func (h *APIHandler) CreateAPIToken(c *gin.Context) {
	if rejectTokenIssuedByToken(c) {
		return
	}
	username := c.GetString("username")
	role := c.GetString("role")
	userPerms := c.GetString("permissions")
	name := c.PostForm("name")
	requestedPerms := c.PostForm("permissions")
	allowedIPs := c.PostForm("allowed_ips")

	if name == "" {
		c.String(http.StatusBadRequest, "Token name required")
		return
	}

	// Security: Input length validation to prevent unconstrained resource consumption
	if len(name) > 255 || len(requestedPerms) > 1024 || len(allowedIPs) > 2048 {
		c.String(http.StatusBadRequest, "Input length exceeds maximum allowed")
		return
	}

	// Validate permissions
	finalPerms := ""
	if requestedPerms != "" {
		if username == h.cfg.GUIAdmin && !c.GetBool("token_auth") {
			// The recovery browser session has the full permission catalog,
			// but stored scopes must still be known permission keys.
			normalized, err := models.NormalizePermissions(requestedPerms)
			if err != nil {
				c.String(http.StatusBadRequest, err.Error())
				return
			}
			finalPerms = normalized
		} else {
			var err error
			finalPerms, err = h.validatePermissionSubset(requestedPerms, userPerms)
			if err != nil {
				c.String(http.StatusForbidden, err.Error())
				return
			}
		}
	}

	// Generate random token using CSPRNG
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		c.String(http.StatusInternalServerError, "failed to generate secure token")
		return
	}
	rawTokenStr := "bl_" + hex.EncodeToString(b)

	// Calculate hash for storage
	hash := sha256.Sum256([]byte(rawTokenStr))
	storedHash := hex.EncodeToString(hash[:])

	token := models.APIToken{
		TokenHash:   storedHash,
		Name:        name,
		Username:    username,
		Role:        role,
		Permissions: finalPerms,
		AllowedIPs:  allowedIPs,
	}

	err := h.pgRepo.CreateAPIToken(token)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to create token")
		return
	}

	_ = h.pgRepo.LogAction(username, "CREATE_TOKEN", name, "API Token created")

	c.Header("HX-Trigger", fmt.Sprintf(`{"newToken": "%s"}`, rawTokenStr))

	tokens, _ := h.pgRepo.GetAPITokens(username)
	h.renderHTML(c, http.StatusOK, "settings_tokens_list.html", gin.H{"tokens": tokens})
}

func (h *APIHandler) DeleteAPIToken(c *gin.Context) {
	username := c.GetString("username")
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	_ = h.pgRepo.DeleteAPIToken(id, username)
	_ = h.pgRepo.LogAction(username, "DELETE_TOKEN", strconv.Itoa(id), "API Token deleted")
	c.Status(http.StatusOK)
}

func (h *APIHandler) UpdateAPITokenPermissions(c *gin.Context) {
	if rejectTokenIssuedByToken(c) {
		return
	}
	username := c.GetString("username")
	userPerms := c.GetString("permissions")
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token id"})
		return
	}

	var req struct {
		Permissions string `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Validate permissions
	finalPerms := ""
	if req.Permissions != "" {
		if username == h.cfg.GUIAdmin && !c.GetBool("token_auth") {
			finalPerms = req.Permissions
		} else {
			var err error
			finalPerms, err = h.validatePermissionSubset(req.Permissions, userPerms)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
				return
			}
		}
	}

	err = h.pgRepo.UpdateAPITokenPermissions(id, username, finalPerms)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update permissions"})
		return
	}

	_ = h.pgRepo.LogAction(username, "UPDATE_TOKEN_PERMS", strconv.Itoa(id), finalPerms)

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) AdminRevokeAPIToken(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	userPerms, _ := c.Get("permissions")
	username := c.GetString("username")
	hasGlobalTokensPerm := false
	for _, p := range strings.Split(userPerms.(string), ",") {
		if strings.TrimSpace(p) == "manage_global_tokens" {
			hasGlobalTokensPerm = true
			break
		}
	}

	if hasGlobalTokensPerm {
		_ = h.pgRepo.DeleteAPITokenByID(id)
		_ = h.pgRepo.LogAction(username, "ADMIN_REVOKE_TOKEN", strconv.Itoa(id), "Token revoked by admin")
		c.Status(http.StatusOK)
	} else {
		c.Status(http.StatusForbidden)
	}
}
