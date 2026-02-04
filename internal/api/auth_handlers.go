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

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
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
						expiresAt, _ := time.Parse(time.RFC3339, *token.ExpiresAt)
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
							Str("client_ip", c.ClientIP()).
							Str("allowed", token.AllowedIPs).
							Msg("API Token used from unauthorized IP")
						c.JSON(http.StatusForbidden, gin.H{"error": "Token not allowed from this IP"})
						c.Abort()
						return
					}

					_ = h.pgRepo.UpdateTokenLastUsed(token.ID, c.ClientIP())
					c.Set("username", token.Username)
					c.Set("role", token.Role)
					c.Set("permissions", token.Permissions)
					c.Next()
					return
				}
			}
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

		username := session.Get("username").(string)

		// Verify user still exists in database
		admin, err := h.pgRepo.GetAdmin(username)
		if err != nil || admin == nil {
			zlog.Warn().Str("username", username).Msg("Session active for non-existent user")
			session.Clear()
			_ = session.Save()
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		c.Set("username", username)

		// Get role and permissions from DB or session
		role := session.Get("role")
		perms := session.Get("permissions")
		if role == nil || perms == nil {
			role = admin.Role
			perms = admin.Permissions
			session.Set("role", role)
			session.Set("permissions", perms)
			_ = session.Save()
		}
		c.Set("role", role.(string))
		c.Set("permissions", perms.(string))

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
		if err != nil || admin == nil {
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

		// System admin bypass
		username, _ := c.Get("username")
		if username == h.cfg.GUIAdmin {
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

func (h *APIHandler) generateQRWithLogo(url string) ([]byte, error) {
	// Generate QR code with High error correction
	qr, err := qrcode.New(url, qrcode.High)
	if err != nil {
		return nil, err
	}

	// Create image from QR code
	img := qr.Image(256)

	// Try to load logo
	logoFile, err := os.Open("cmd/server/static/cd/favicon-color.png")
	if err != nil {
		// Fallback to plain QR if logo not found
		return qr.PNG(256)
	}
	defer logoFile.Close()

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

func (h *APIHandler) VerifyFirstFactor(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if h.cfg.DisableGUIAdminLogin && username == h.cfg.GUIAdmin {
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "GUIAdmin login is disabled"})
		return
	}

	admin, err := h.pgRepo.GetAdmin(username)
	if err != nil {
		_ = h.pgRepo.LogAction("system", "LOGIN_FAILURE", username, "Invalid Operator ID (Enumeration Protection)")
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
	if err != nil {
		_ = h.pgRepo.LogAction(username, "LOGIN_FAILURE", c.ClientIP(), "Invalid Password (Enumeration Protection)")
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

	if h.cfg.DisableGUIAdminLogin && username == h.cfg.GUIAdmin {
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "GUIAdmin login is disabled"})
		return
	}

	session := sessions.Default(c)

	// Check for pending auth session if password is not provided (multi-step)
	isMultiStep := false
	if password == "" {
		pendingUser := session.Get("pending_auth_user")
		pendingVerified := session.Get("pending_auth_verified")
		if pendingUser == nil || pendingUser.(string) != username || pendingVerified == nil || !pendingVerified.(bool) {
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
		pendingVerified := session.Get("pending_auth_verified")
		pendingSecret := session.Get("pending_totp_secret")
		admin, _ := h.pgRepo.GetAdmin(username)

		if pendingVerified == nil || !pendingVerified.(bool) || pendingSecret == nil || pendingSecret.(string) != setupSecret {
			zlog.Warn().Str("username", username).Msg("Unauthenticated or invalid TOTP setup attempt")
			_ = h.pgRepo.LogAction(username, "LOGIN_FAILURE", c.ClientIP(), "Unauthenticated TOTP setup attempt")
			h.renderHTML(c, http.StatusOK, "login.html", gin.H{
				"error":    "Session expired or invalid setup attempt.",
				"username": username,
			})
			return
		}

		// Prevent overwriting existing token via this flow
		if admin != nil && admin.Token != "" {
			zlog.Warn().Str("username", username).Msg("Attempt to overwrite existing TOTP token")
			_ = h.pgRepo.LogAction(username, "SECURITY_WARNING", c.ClientIP(), "Attempt to overwrite existing TOTP token")
			h.renderHTML(c, http.StatusOK, "login.html", gin.H{
				"error":    "2FA is already configured for this account.",
				"username": username,
			})
			return
		}

		if totp.Validate(totpCode, setupSecret) {
			// Save the secret to the user
			_ = h.pgRepo.UpdateAdminToken(username, setupSecret)
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
	if isMultiStep {
		authenticated = h.authService.VerifyTOTP(username, totpCode)
	} else {
		authenticated = h.authService.CheckAuth(username, password, totpCode)
	}

	if authenticated {
		session.Delete("pending_auth_user")
		session.Delete("pending_auth_verified")
		session.Delete("pending_totp_secret")
		session.Set("logged_in", true)
		session.Set("username", username)
		session.Set("client_ip", c.ClientIP())
		session.Set("login_time", time.Now().UTC().Format(time.RFC3339))
		session.Set("sudo_time", time.Now().Unix()) // Initial sudo mode
		admin, _ := h.pgRepo.GetAdmin(username)
		if admin != nil {
			session.Set("role", admin.Role)
			session.Set("permissions", admin.Permissions)
			session.Set("session_version", admin.SessionVersion)
		}
		if err := session.Save(); err != nil {
			zlog.Error().Err(err).Msg("Failed to save session during login")
		}

		_ = h.pgRepo.LogAction(username, "LOGIN_SUCCESS", c.ClientIP(), "")

		c.Redirect(http.StatusFound, "/dashboard")
		return
	}

	// On failed login, clear pending state to be safe
	session.Delete("pending_auth_user")
	session.Delete("pending_auth_verified")
	session.Delete("pending_totp_secret")
	_ = session.Save()

	_ = h.pgRepo.LogAction(username, "LOGIN_FAILURE", c.ClientIP(), "Invalid TOTP or Credentials")

	h.renderHTML(c, http.StatusOK, "login.html", gin.H{
		"error":    "Invalid credentials or TOTP code",
		"username": username,
		"step":     "totp",
	})
}

func (h *APIHandler) SudoMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
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
	h.renderHTML(c, http.StatusOK, "login.html", gin.H{"step": "totp", "is_sudo": true, "next": c.Query("next"), "username": c.GetString("username")})
}

func (h *APIHandler) VerifySudo(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username").(string)
	totpCode := c.PostForm("totp")
	next := c.PostForm("next")
	if next == "" {
		next = c.Query("next")
	}

	admin, _ := h.pgRepo.GetAdmin(username)
	if admin != nil && totp.Validate(totpCode, admin.Token) {
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
	session := sessions.Default(c)
	session.Clear()
	_ = session.Save()
	c.Redirect(http.StatusFound, "/login")
}

func (h *APIHandler) CreateAPIToken(c *gin.Context) {
	username, _ := c.Get("username")
	role, _ := c.Get("role")
	userPerms, _ := c.Get("permissions")
	name := c.PostForm("name")
	requestedPerms := c.PostForm("permissions")
	allowedIPs := c.PostForm("allowed_ips")

	if name == "" {
		c.String(http.StatusBadRequest, "Token name required")
		return
	}

	// Validate permissions
	finalPerms := ""
	if requestedPerms != "" {
		rPerms := strings.Split(requestedPerms, ",")

		if username == h.cfg.GUIAdmin {
			// Superuser can grant any permissions to a token
			finalPerms = requestedPerms
		} else {
			// Other users can only grant a subset of their own permissions
			uPerms := strings.Split(userPerms.(string), ",")
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
					c.String(http.StatusForbidden, fmt.Sprintf("insufficient permissions to grant: %s", rp))
					return
				}
			}
			finalPerms = strings.Join(validPerms, ",")
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
		Username:    username.(string),
		Role:        role.(string),
		Permissions: finalPerms,
		AllowedIPs:  allowedIPs,
	}

	err := h.pgRepo.CreateAPIToken(token)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to create token")
		return
	}

	c.Header("HX-Trigger", fmt.Sprintf(`{"newToken": "%s"}`, rawTokenStr))

	tokens, _ := h.pgRepo.GetAPITokens(username.(string))
	h.renderHTML(c, http.StatusOK, "settings_tokens_list.html", gin.H{"tokens": tokens})
}

func (h *APIHandler) DeleteAPIToken(c *gin.Context) {
	username, _ := c.Get("username")
	id, _ := strconv.Atoi(c.Param("id"))

	_ = h.pgRepo.DeleteAPIToken(id, username.(string))
	c.Status(http.StatusOK)
}

func (h *APIHandler) UpdateAPITokenPermissions(c *gin.Context) {
	username, _ := c.Get("username")
	userPerms, _ := c.Get("permissions")
	id, _ := strconv.Atoi(c.Param("id"))

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
		if username == h.cfg.GUIAdmin {
			finalPerms = req.Permissions
		} else {
			rPerms := strings.Split(req.Permissions, ",")
			uPerms := strings.Split(userPerms.(string), ",")
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
					c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("insufficient permissions to grant: %s", rp)})
					return
				}
			}
			finalPerms = strings.Join(validPerms, ",")
		}
	}

	err := h.pgRepo.UpdateAPITokenPermissions(id, username.(string), finalPerms)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update permissions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) AdminRevokeAPIToken(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))

	userPerms, _ := c.Get("permissions")
	hasGlobalTokensPerm := false
	for _, p := range strings.Split(userPerms.(string), ",") {
		if strings.TrimSpace(p) == "manage_global_tokens" {
			hasGlobalTokensPerm = true
			break
		}
	}

	if hasGlobalTokensPerm {
		_ = h.pgRepo.DeleteAPITokenByID(id)
		c.Status(http.StatusOK)
	} else {
		c.Status(http.StatusForbidden)
	}
}
