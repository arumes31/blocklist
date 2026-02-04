package api

import (
	"blocklist/internal/config"
	"blocklist/internal/metrics"
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"blocklist/internal/service"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"image"
	"image/draw"
	"image/png"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	zlog "github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

type APIHandler struct {
	cfg            *config.Config
	redisRepo      *repository.RedisRepository
	pgRepo         *repository.PostgresRepository
	authService    *service.AuthService
	ipService      *service.IPService
	hub            *Hub
	webhookService *service.WebhookService
	mainLimiter    gin.HandlerFunc
	loginLimiter   gin.HandlerFunc
	webhookLimiter gin.HandlerFunc
}

// NewAPIHandler creates a new instance of APIHandler with the necessary dependencies.
func NewAPIHandler(cfg *config.Config, r *repository.RedisRepository, pg *repository.PostgresRepository, auth *service.AuthService, ip *service.IPService, hub *Hub, wh *service.WebhookService) *APIHandler {
	return &APIHandler{
		cfg:            cfg,
		redisRepo:      r,
		pgRepo:         pg,
		authService:    auth,
		ipService:      ip,
		hub:            hub,
		webhookService: wh,
	}
}

func (h *APIHandler) SetLimiters(main, login, webhook gin.HandlerFunc) {
	h.mainLimiter = main
	h.loginLimiter = login
	h.webhookLimiter = webhook
}

// renderHTML is a helper to render templates with common data like the CSP nonce.
func (h *APIHandler) renderHTML(c *gin.Context, status int, name string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	if nonce, exists := c.Get("nonce"); exists {
		data["nonce"] = nonce
	}
	c.HTML(status, name, data)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:    1024,
	WriteBufferSize:   1024,
	EnableCompression: true,
	CheckOrigin: func(r *http.Request) bool {
		// More permissive for production behind proxies
		return true
	},
}

func (h *APIHandler) WS(c *gin.Context) {
	// Require authenticated session
	session := sessions.Default(c)
	if loggedIn := session.Get("logged_in"); loggedIn == nil || !loggedIn.(bool) {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		zlog.Error().Err(err).
			Str("host", c.Request.Host).
			Msg("WebSocket upgrade failed")
		return
	}

	h.hub.register <- conn

	// Keep-alive setup
	pingTicker := time.NewTicker(30 * time.Second)
	defer func() {
		pingTicker.Stop()
		h.hub.unregister <- conn
	}()

	_ = conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		return nil
	})

	done := make(chan struct{})
	// Read loop in a goroutine
	go func() {
		defer close(done)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()

	// Write loop for keep-alive
	for {
		select {
		case <-pingTicker.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-done:
			return
		case <-c.Request.Context().Done():
			return
		}
	}
}

func (h *APIHandler) PrometheusMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		if path == "" {
			path = "unknown"
		}
		c.Next()
		duration := time.Since(start).Seconds()
		status := strconv.Itoa(c.Writer.Status())
		metrics.MetricHttpDuration.WithLabelValues(path, c.Request.Method, status).Observe(duration)
	}
}

func (h *APIHandler) isValidRedirect(target string) bool {
	if target == "" {
		return false
	}
	// Only allow local paths starting with /
	// Disallow // which some browsers interpret as protocol-relative (e.g. //evil.com)
	// Disallow /\ which can be used to trick some parsers
	return strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") && !strings.HasPrefix(target, "/\\")
}

// RegisterRoutes sets up all the API and UI routes for the application.
func (h *APIHandler) RegisterRoutes(r *gin.Engine) {
	r.Use(h.PrometheusMiddleware())
	// Public UI routes
	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, "/dashboard") })

	login := r.Group("/login")
	login.Use(h.loginLimiter)
	{
		login.GET("", h.ShowLogin)
		login.POST("", h.Login)
		login.POST("/verify", h.VerifyFirstFactor)
	}

	r.GET("/logout", h.Logout)
	r.GET("/ws", h.WS)
	r.GET("/sudo", h.AuthMiddleware(), h.loginLimiter, h.ShowSudo)
	r.POST("/sudo", h.AuthMiddleware(), h.loginLimiter, h.VerifySudo)

	// API Versioning (Improvement 5)
	v1 := r.Group("/api/v1")
	{
		v1.GET("/raw", h.RawIPs) // Public
	}

	v1auth := v1.Group("/")
	v1auth.Use(h.AuthMiddleware())
	v1auth.Use(h.SessionCheckMiddleware())
	{
		// Data viewing requires view_ips and main limiter
		v1auth.GET("/ips", h.mainLimiter, h.PermissionMiddleware("view_ips"), h.IPsPaginated)
		v1auth.GET("/ips_list", h.mainLimiter, h.PermissionMiddleware("view_ips"), h.JSONIPs)
		v1auth.GET("/whitelists", h.mainLimiter, h.PermissionMiddleware("view_ips"), h.JSONWhitelists)
		v1auth.GET("/ips/:ip/details", h.mainLimiter, h.PermissionMiddleware("view_ips"), h.GetIPDetails)

		// Exports require export_data
		v1auth.GET("/ips/export", h.mainLimiter, h.PermissionMiddleware("export_data"), h.SudoMiddleware(), h.ExportIPs)

		// Stats require view_stats
		v1auth.GET("/stats", h.mainLimiter, h.PermissionMiddleware("view_stats"), h.Stats)
	}

	// Webhooks handle their own granular permission checks and multiple auth types
	v1.POST("/webhook", h.AuthMiddleware(), h.SessionCheckMiddleware(), h.webhookLimiter, h.Webhook)

	r.GET("/openapi.json", h.OpenAPI)
	r.GET("/docs", h.AuthMiddleware(), h.SessionCheckMiddleware(), func(c *gin.Context) {
		session := sessions.Default(c)
		username := session.Get("username")
		permissions, _ := c.Get("permissions")
		h.renderHTML(c, http.StatusOK, "docs.html", gin.H{
			"username":       username,
			"permissions":    permissions,
			"admin_username": h.cfg.GUIAdmin,
		})
	})

	// Protected UI routes
	auth := r.Group("/")
	auth.Use(h.AuthMiddleware())
	auth.Use(h.SessionCheckMiddleware())
	auth.Use(h.mainLimiter)
	{
		// Dashboard requires view_ips and view_stats
		auth.GET("/dashboard", h.PermissionMiddleware("view_ips"), h.Dashboard)
		auth.GET("/thread-map", h.PermissionMiddleware("view_ips"), h.ThreadMap)
		auth.GET("/dashboard/table", h.PermissionMiddleware("view_ips"), h.DashboardTable) // For HTMX polling

		auth.GET("/api/v1/views", h.PermissionMiddleware("view_ips"), h.GetSavedViews)
		auth.POST("/api/v1/views", h.PermissionMiddleware("view_ips"), h.CreateSavedView)
		auth.DELETE("/api/v1/views/:id", h.PermissionMiddleware("view_ips"), h.DeleteSavedView)

		auth.GET("/settings", h.PermissionMiddleware("manage_webhooks"), h.Settings)
		auth.POST("/api/v1/settings/webhooks", h.PermissionMiddleware("manage_webhooks"), h.AddOutboundWebhook)
		auth.DELETE("/api/v1/settings/webhooks/:id", h.PermissionMiddleware("manage_webhooks"), h.DeleteOutboundWebhook)

		// API Tokens
		auth.POST("/api/v1/settings/tokens", h.PermissionMiddleware("manage_api_tokens"), h.CreateAPIToken)
		auth.DELETE("/api/v1/settings/tokens/:id", h.PermissionMiddleware("manage_api_tokens"), h.DeleteAPIToken)
		auth.POST("/api/v1/settings/tokens/:id/permissions", h.PermissionMiddleware("manage_api_tokens"), h.UpdateAPITokenPermissions)
		auth.DELETE("/api/v1/admin/tokens/:id", h.PermissionMiddleware("manage_global_tokens"), h.SudoMiddleware(), h.AdminRevokeAPIToken)

		// Enforcement actions
		auth.POST("/block", h.PermissionMiddleware("block_ips"), h.BlockIP)
		auth.POST("/unblock", h.PermissionMiddleware("unblock_ips"), h.UnblockIP)
		auth.POST("/bulk_block", h.PermissionMiddleware("block_ips"), h.BulkBlock)
		auth.POST("/bulk_unblock", h.PermissionMiddleware("unblock_ips"), h.BulkUnblock)

		// Whitelist management
		auth.GET("/whitelist", h.PermissionMiddleware("manage_whitelist", "whitelist_ips"), h.Whitelist)
		auth.POST("/add_whitelist", h.PermissionMiddleware("manage_whitelist", "whitelist_ips"), h.AddWhitelist)
		auth.POST("/remove_whitelist", h.PermissionMiddleware("manage_whitelist"), h.RemoveWhitelist)

		// Admin management
		admin := auth.Group("/admin_management")
		admin.Use(h.PermissionMiddleware("manage_admins"))
		{
			admin.GET("", h.AdminManagement)
			admin.POST("/create", h.CreateAdmin)
			admin.POST("/delete", h.SudoMiddleware(), h.DeleteAdmin)
			admin.POST("/change_password", h.ChangeAdminPassword)
			admin.POST("/change_totp", h.ChangeAdminTOTP)
			admin.POST("/change_permissions", h.ChangeAdminPermissions)
			admin.GET("/get_qr/:username", h.GetQR)
		}
	}

	r.GET("/health", h.Health)
	r.GET("/ready", h.Ready)
	r.GET("/metrics", h.MetricsAuthMiddleware(), gin.WrapH(promhttp.Handler()))
}

// getCombinedIPs fetches blocked IPs from Redis and enriches them with persistent blocks from Postgres (cached).
func (h *APIHandler) getCombinedIPs() map[string]models.IPEntry {
	ips, _ := h.redisRepo.GetBlockedIPs()

	if h.pgRepo != nil {
		var pIps map[string]models.IPEntry
		// Try cache first
		err := h.redisRepo.GetCache("persistent_ips_cache", &pIps)
		if err != nil {
			// Cache miss, fetch from DB
			pIps, _ = h.pgRepo.GetPersistentBlocks()
			// Set cache for 1 minute
			_ = h.redisRepo.SetCache("persistent_ips_cache", pIps, 1*time.Minute)
		}

		for ip, data := range pIps {
			ips[ip] = data
		}
	}
	return ips
}

// Dashboard renders the main dashboard page.
func (h *APIHandler) Dashboard(c *gin.Context) {
	username, _ := c.Get("username")

	ips := h.getCombinedIPs()

	// Preload stats for initial render
	hour, day, totalEver, activeBlocks, top, topASN, topReason, wh, lb, bm, _ := h.ipService.Stats(c.Request.Context())

	tops := make([]map[string]interface{}, 0, len(top))
	for _, t := range top {
		tops = append(tops, map[string]interface{}{"Country": t.Country, "Count": t.Count})
	}

	asns := make([]map[string]interface{}, 0, len(topASN))
	for _, a := range topASN {
		asns = append(asns, map[string]interface{}{"ASN": a.ASN, "ASNOrg": a.ASNOrg, "Count": a.Count})
	}

	reasons := make([]map[string]interface{}, 0, len(topReason))
	for _, r := range topReason {
		reasons = append(reasons, map[string]interface{}{"Reason": r.Reason, "Count": r.Count})
	}

	views, _ := h.pgRepo.GetSavedViews(username.(string))
	permissions, _ := c.Get("permissions")

	h.renderHTML(c, http.StatusOK, "dashboard.html", gin.H{
		"ips":            ips,
		"total_ips":      activeBlocks, // Use value from Stats() for consistency
		"admin_username": h.cfg.GUIAdmin,
		"username":       username,
		"permissions":    permissions,
		"views":          views,
		"stats": gin.H{
			"hour":          hour,
			"day":           day,
			"total":         totalEver, // Persistent total bans
			"top_countries": tops,
			"top_asns":      asns,
			"top_reasons":   reasons,
			"webhooks_hour": wh,
			"last_block_ts": lb,
			"blocks_minute": bm,
		},
	})
}

func (h *APIHandler) ThreadMap(c *gin.Context) {
	ips := h.getCombinedIPs()
	totalCount := len(ips)
	username, _ := c.Get("username")
	permissions, _ := c.Get("permissions")

	hour, day, _, _, top, _, _, _, _, _, _ := h.ipService.Stats(c.Request.Context())

	tops := make([]map[string]interface{}, 0, len(top))
	for _, t := range top {
		tops = append(tops, map[string]interface{}{"Country": t.Country, "Count": t.Count})
	}

	h.renderHTML(c, http.StatusOK, "thread_map.html", gin.H{
		"total_ips":      totalCount,
		"admin_username": h.cfg.GUIAdmin,
		"username":       username,
		"permissions":    permissions,
		"stats": gin.H{
			"hour":          hour,
			"day":           day,
			"top_countries": tops,
		},
	})
}

func (h *APIHandler) GetSavedViews(c *gin.Context) {
	username, _ := c.Get("username")
	views, err := h.pgRepo.GetSavedViews(username.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch views"})
		return
	}
	c.JSON(http.StatusOK, views)
}

func (h *APIHandler) CreateSavedView(c *gin.Context) {
	username, _ := c.Get("username")
	var req struct {
		Name    string `json:"name"`
		Filters string `json:"filters"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	view := models.SavedView{
		Username: username.(string),
		Name:     req.Name,
		Filters:  req.Filters,
	}

	err := h.pgRepo.CreateSavedView(view)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save view"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) DeleteSavedView(c *gin.Context) {
	username, _ := c.Get("username")
	id, _ := strconv.Atoi(c.Param("id"))

	err := h.pgRepo.DeleteSavedView(id, username.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete view"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// For HTMX Polling (Improvement 4)
func (h *APIHandler) DashboardTable(c *gin.Context) {
	ips := h.getCombinedIPs()
	h.renderHTML(c, http.StatusOK, "dashboard_table.html", gin.H{
		"ips": ips,
	})
}

func (h *APIHandler) Health(c *gin.Context) {
	status := "UP"
	dbStatus := "OK"
	readDbStatus := "OK"
	redisStatus := "OK"
	if h.redisRepo != nil {
		if _, err := h.redisRepo.HGetAllRaw("ips"); err != nil {
			redisStatus = "ERROR"
			status = "DEGRADED"
		}
	} else {
		redisStatus = "MISSING"
		status = "DEGRADED"
	}
	if h.pgRepo != nil {
		if _, err := h.pgRepo.GetAllAdmins(); err != nil {
			dbStatus = "ERROR"
			status = "DEGRADED"
		}
		// Check read replica if it's different from primary
		// We'll add a Ping method to repository later if needed,
		// for now we just use a simple read-only query.
		if _, err := h.pgRepo.GetPersistentCount(); err != nil {
			readDbStatus = "ERROR"
			status = "DEGRADED"
		}
	}
	c.JSON(200, gin.H{
		"status":        status,
		"postgres":      dbStatus,
		"postgres_read": readDbStatus,
		"redis":         redisStatus,
	})
}

func (h *APIHandler) isIPInCIDRs(ipStr string, cidrs string) bool {
	if cidrs == "" {
		return true // No restriction
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range strings.Split(cidrs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			if network.Contains(ip) {
				return true
			}
		} else {
			// Try as plain IP
			if cidr == ipStr {
				return true
			}
		}
	}
	return false
}

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
				token, err := h.pgRepo.GetAPITokenByHash(tokenStr)
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
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "Invalid Operator ID"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
	if err != nil {
		h.renderHTML(c, http.StatusOK, "login_error.html", gin.H{"error": "Access Denied"})
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
			h.renderHTML(c, http.StatusOK, "login.html", gin.H{
				"error": "Session expired or invalid login attempt. Please restart login.",
			})
			return
		}
		isMultiStep = true
	}

	// If it's a setup attempt
	if setupSecret != "" {
		if totp.Validate(totpCode, setupSecret) {
			// Save the secret to the user
			_ = h.pgRepo.UpdateAdminToken(username, setupSecret)
		} else {
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
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}

	// On failed login, clear pending state to be safe
	session.Delete("pending_auth_user")
	session.Delete("pending_auth_verified")
	_ = session.Save()

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

// BlockIP handles the request to block an IP address.
func (h *APIHandler) BlockIP(c *gin.Context) {
	username, _ := c.Get("username")

	var req struct {
		IP      string `json:"ip"`
		Persist bool   `json:"persist"`
		Reason  string `json:"reason"`
		TTL     int    `json:"ttl"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error"})
		return
	}

	if !h.ipService.IsValidIP(req.IP) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "invalid IP"})
		return
	}

	geo := h.ipService.GetGeoIP(req.IP)
	now := time.Now().UTC()
	timestamp := now.Format("2006-01-02 15:04:05 UTC")

	expiresAt := ""
	if !req.Persist {
		ttl := 86400 // 24h default
		if req.TTL > 0 {
			ttl = req.TTL
		}
		expiresAt = now.Add(time.Duration(ttl) * time.Second).Format("2006-01-02 15:04:05 UTC")
	}

	reason := req.Reason
	if reason == "" {
		if req.Persist {
			reason = "~~manually-added--persist"
		} else {
			reason = "~~manually-added"
		}
	}

	entry := models.IPEntry{
		Timestamp:   timestamp,
		Geolocation: geo,
		Reason:      reason,
		AddedBy:     fmt.Sprintf("%s (%s)", username.(string), c.ClientIP()),
		TTL:         req.TTL,
		ExpiresAt:   expiresAt,
		ThreatScore: h.ipService.CalculateThreatScore(req.IP, reason),
	}

	if req.Persist && h.pgRepo != nil {
		_ = h.pgRepo.CreatePersistentBlock(req.IP, entry)
		_ = h.pgRepo.LogAction(username.(string), "BLOCK_PERSISTENT", req.IP, req.Reason)
	} else {
		if h.pgRepo != nil {
			_ = h.pgRepo.LogAction(username.(string), "BLOCK_EPHEMERAL", req.IP, req.Reason)
		}
	}
	// Atomic operation updates hash, ZSET index, and persistent counters
	_ = h.redisRepo.ExecBlockAtomic(req.IP, entry, now)

	metrics.MetricBlocksTotal.WithLabelValues("gui").Inc()

	h.hub.BroadcastEvent("block", map[string]interface{}{
		"ip":   req.IP,
		"data": entry,
	})
	h.webhookService.Notify(c.Request.Context(), "block", map[string]interface{}{"ip": req.IP, "data": entry})

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// UnblockIP handles the request to unblock an IP address.
func (h *APIHandler) UnblockIP(c *gin.Context) {
	username, _ := c.Get("username")

	var req struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		zlog.Error().Err(err).Msg("UnblockIP: invalid request body")
		c.JSON(http.StatusBadRequest, gin.H{"status": "error"})
		return
	}

	// Atomic unblock from Redis
	_ = h.redisRepo.ExecUnblockAtomic(req.IP)

	if h.pgRepo != nil {
		_ = h.pgRepo.DeletePersistentBlock(req.IP)
		_ = h.pgRepo.LogAction(username.(string), "UNBLOCK", req.IP, "")
	}

	metrics.MetricUnblocksTotal.WithLabelValues("gui").Inc()
	h.hub.BroadcastEvent("unblock", map[string]interface{}{
		"ip": req.IP,
	})
	h.webhookService.Notify(c.Request.Context(), "unblock", map[string]interface{}{"ip": req.IP})

	if c.GetHeader("HX-Request") != "" {
		c.Status(http.StatusOK)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) BulkBlock(c *gin.Context) {
	username, _ := c.Get("username")
	var req struct {
		IPs     []string `json:"ips"`
		Persist bool     `json:"persist"`
		Reason  string   `json:"reason"`
		TTL     int      `json:"ttl"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	err := h.ipService.BulkBlock(c.Request.Context(), req.IPs, req.Reason, username.(string), c.ClientIP(), req.Persist, req.TTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "bulk block failed"})
		return
	}

	h.webhookService.Notify(c.Request.Context(), "bulk_block", map[string]interface{}{"ips": req.IPs})

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) BulkUnblock(c *gin.Context) {
	username, _ := c.Get("username")
	var req struct {
		IPs []string `json:"ips"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	err := h.ipService.BulkUnblock(c.Request.Context(), req.IPs, username.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "bulk unblock failed"})
		return
	}

	h.webhookService.Notify(c.Request.Context(), "bulk_unblock", map[string]interface{}{"ips": req.IPs})

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) Whitelist(c *gin.Context) {
	ips, _ := h.redisRepo.GetWhitelistedIPs()

	subnets := []string{}
	for _, sStr := range strings.Split(h.cfg.BlockedRanges, ",") {
		sStr = strings.TrimSpace(sStr)
		if sStr != "" {
			subnets = append(subnets, sStr)
		}
	}

	username, _ := c.Get("username")
	permissions, _ := c.Get("permissions")

	h.renderHTML(c, http.StatusOK, "whitelist.html", gin.H{
		"whitelisted_ips": ips,
		"blocked_subnets": subnets,
		"admin_username":  h.cfg.GUIAdmin,
		"username":        username,
		"permissions":     permissions,
	})
}

func (h *APIHandler) AddWhitelist(c *gin.Context) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"status": "error"})
		return
	}

	geo := h.ipService.GetGeoIP(req.IP)
	entry := models.WhitelistEntry{
		Timestamp:   time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Geolocation: geo,
		AddedBy:     "GUI",
		Reason:      req.Reason,
	}
	_ = h.redisRepo.WhitelistIP(req.IP, entry)

	h.hub.BroadcastEvent("whitelist", map[string]interface{}{
		"ip":   req.IP,
		"data": entry,
	})

	c.JSON(200, gin.H{"status": "success"})
}

func (h *APIHandler) RemoveWhitelist(c *gin.Context) {
	var req struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"status": "error"})
		return
	}
	_ = h.redisRepo.RemoveFromWhitelist(req.IP)

	h.hub.BroadcastEvent("unwhitelist", map[string]interface{}{
		"ip": req.IP,
	})

	c.JSON(200, gin.H{"status": "success"})
}

func (h *APIHandler) Webhook(c *gin.Context) {
	// Webhook requires authentication (Bearer token via AuthMiddleware)
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
		return
	}

	var data struct {
		IP      string `json:"ip"`
		Reason  string `json:"reason"`
		Act     string `json:"act"`
		TTL     int    `json:"ttl"`
		Persist bool   `json:"persist"`
	}

	if err := c.ShouldBindJSON(&data); err != nil {
		zlog.Error().Err(err).Msg("Webhook: failed to bind JSON")
		c.JSON(400, gin.H{"status": "invalid request"})
		return
	}

	// Determine required permission based on action
	requiredPerm := ""
	if data.Act == "ban" || data.Act == "ban-ip" {
		requiredPerm = "block_ips"
	} else if data.Act == "unban" || data.Act == "delete-ban" {
		requiredPerm = "unblock_ips"
	} else if data.Act == "whitelist" {
		requiredPerm = "whitelist_ips"
	} else {
		c.JSON(501, gin.H{"status": "action not implemented"})
		return
	}

	// Check for granular permission
	if username.(string) != h.cfg.GUIAdmin {
		perms, _ := c.Get("permissions")
		permStr := perms.(string)

		hasAccess := false
		for _, p := range strings.Split(permStr, ",") {
			if strings.TrimSpace(p) == requiredPerm {
				hasAccess = true
				break
			}
		}

		if !hasAccess {
			zlog.Warn().Str("username", username.(string)).Str("permissions", permStr).Str("required", requiredPerm).Msg("Webhook access denied: insufficient permissions")
			c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("Webhook access denied (requires %s)", requiredPerm)})
			return
		}
	}

	if data.IP == "" || !h.ipService.IsValidIP(data.IP) {
		c.JSON(400, gin.H{"status": "invalid IP"})
		return
	}

	metrics.MetricWebhooksTotal.Inc()
	_ = h.redisRepo.IndexWebhookHit(time.Now().UTC())

	timestamp := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	geo := h.ipService.GetGeoIP(data.IP)
	now := time.Now().UTC()

	expiresAt := ""
	if !data.Persist {
		tVal := 86400
		if data.TTL > 0 {
			tVal = data.TTL
		}
		expiresAt = now.Add(time.Duration(tVal) * time.Second).Format("2006-01-02 15:04:05 UTC")
	}

	sourceIP := c.ClientIP()
	addedBy := fmt.Sprintf("Webhook (%s:%s)", username.(string), sourceIP)

	sourceGeo := h.ipService.GetGeoIP(sourceIP)

	entry := models.IPEntry{
		Timestamp:   timestamp,
		Geolocation: geo,
		Reason:      data.Reason,
		AddedBy:     addedBy,
		TTL:         data.TTL,
		ExpiresAt:   expiresAt,
		ThreatScore: h.ipService.CalculateThreatScore(data.IP, data.Reason),
	}

	if data.Act == "ban" || data.Act == "ban-ip" {
		if data.Persist && h.pgRepo != nil {
			_ = h.pgRepo.CreatePersistentBlock(data.IP, entry)
		}

		// Atomic operation updates hash, ZSET index, and persistent counters
		_ = h.redisRepo.ExecBlockAtomic(data.IP, entry, now)

		metrics.MetricBlocksTotal.WithLabelValues("webhook").Inc()
		h.hub.BroadcastEvent("block", map[string]interface{}{
			"ip":         data.IP,
			"data":       entry,
			"source_geo": sourceGeo,
		})
		c.JSON(200, gin.H{"status": "IP banned", "ip": data.IP})
	} else if data.Act == "unban" || data.Act == "delete-ban" {
		_ = h.pgRepo.LogAction(addedBy, "UNBLOCK", data.IP, "webhook unban")
		h.hub.BroadcastEvent("unblock", map[string]interface{}{"ip": data.IP})
		c.JSON(200, gin.H{"status": "IP unbanned", "ip": data.IP})
	} else if data.Act == "whitelist" {
		targetIP := data.IP
		if targetIP == "" {
			targetIP = c.ClientIP()
		}

		// Proceeding with whitelist even if IsValidIP returns false (e.g. already whitelisted or protected range)
		// as explicit whitelisting should override those checks.

		geo := h.ipService.GetGeoIP(targetIP)

		entry := models.WhitelistEntry{
			Timestamp:   timestamp,
			Geolocation: geo,
			AddedBy:     fmt.Sprintf("WebhookWhitelist (%s:%s)", username.(string), sourceIP),
			Reason:      data.Reason,
		}
		if entry.Reason == "" {
			entry.Reason = "Webhook Whitelist"
		}

		_ = h.redisRepo.WhitelistIP(targetIP, entry)

		h.hub.BroadcastEvent("whitelist", map[string]interface{}{
			"ip":         targetIP,
			"data":       entry,
			"source_geo": sourceGeo,
		})

		c.JSON(http.StatusOK, gin.H{"status": "IP whitelisted", "ip": targetIP})
	}
}

func (h *APIHandler) CreateAdmin(c *gin.Context) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Role        string `json:"role"`
		Permissions string `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	if req.Role == "" {
		req.Role = "operator"
	}
	if req.Permissions == "" {
		req.Permissions = "gui_read"
	}

	admin, err := h.authService.CreateAdmin(req.Username, req.Password, req.Role, req.Permissions)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "success", "username": admin.Username})
}

func (h *APIHandler) ChangeAdminPermissions(c *gin.Context) {
	session := sessions.Default(c)
	actor, _ := session.Get("username").(string)

	var req struct {
		Username    string `json:"username"`
		Permissions string `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	if req.Username == h.cfg.GUIAdmin {
		c.JSON(400, gin.H{"error": "cannot change main admin permissions"})
		return
	}

	// Get old perms for logging
	oldAdmin, _ := h.pgRepo.GetAdmin(req.Username)
	oldPerms := ""
	if oldAdmin != nil {
		oldPerms = oldAdmin.Permissions
	}

	err := h.pgRepo.UpdateAdminPermissions(req.Username, req.Permissions)
	if err != nil {
		c.JSON(500, gin.H{"error": "database error"})
		return
	}

	// Enriched audit log
	_ = h.pgRepo.LogAction(actor, "CHANGE_PERMISSIONS", req.Username, fmt.Sprintf("From [%s] to [%s]", oldPerms, req.Permissions))

	c.JSON(200, gin.H{"status": "success"})
}

func (h *APIHandler) AdminManagement(c *gin.Context) {
	username, _ := c.Get("username")
	admins, _ := h.pgRepo.GetAllAdmins()
	adminMap := make(map[string]models.AdminAccount)
	for _, a := range admins {
		adminMap[a.Username] = a
	}

	logs, _ := h.pgRepo.GetAuditLogs(100)
	userPerms, _ := c.Get("permissions")

	h.renderHTML(c, http.StatusOK, "admin_management.html", gin.H{
		"admins":         adminMap,
		"audit_logs":     logs,
		"permissions":    userPerms.(string),
		"username":       username.(string),
		"admin_username": h.cfg.GUIAdmin,
	})
}

func (h *APIHandler) DeleteAdmin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	if req.Username == h.cfg.GUIAdmin {
		c.JSON(400, gin.H{"error": "cannot delete main admin"})
		return
	}

	err := h.pgRepo.DeleteAdmin(req.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": "database error"})
		return
	}

	// Log deletion
	session := sessions.Default(c)
	actor, _ := session.Get("username").(string)
	_ = h.pgRepo.LogAction(actor, "DELETE_ADMIN", req.Username, "User account and all associated tokens removed")

	c.JSON(200, gin.H{"status": "success"})
}

func (h *APIHandler) ChangeAdminPassword(c *gin.Context) {
	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	if req.Username == h.cfg.GUIAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Password for GUIAdmin cannot be changed via UI"})
		return
	}

	hash, _ := h.authService.HashPassword(req.NewPassword)
	err := h.pgRepo.UpdateAdminPassword(req.Username, hash)
	if err != nil {
		c.JSON(500, gin.H{"error": "database error"})
		return
	}

	c.JSON(200, gin.H{"status": "success"})
}

func (h *APIHandler) ChangeAdminTOTP(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	// Clear TOTP secret to force re-setup on next login
	_ = h.pgRepo.UpdateAdminToken(req.Username, "")

	c.JSON(200, gin.H{"status": "success"})
}

func (h *APIHandler) GetQR(c *gin.Context) {
	username := c.Param("username")
	admin, err := h.pgRepo.GetAdmin(username)
	if err != nil {
		c.AbortWithStatus(404)
		return
	}

	// Reconstruct the TOTP URL
	url := fmt.Sprintf("otpauth://totp/Blocklist%%20App:%s?secret=%s&issuer=Blocklist%%20App", username, admin.Token)
	pngData, err := h.generateQRWithLogo(url)
	if err != nil {
		simplePng, _ := qrcode.Encode(url, qrcode.Medium, 256)
		pngData = simplePng
	}
	c.Data(200, "image/png", pngData)
}

func (h *APIHandler) JSONWhitelists(c *gin.Context) {
	ips, err := h.redisRepo.GetWhitelistedIPs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch whitelists"})
		return
	}

	type item struct {
		IP   string                `json:"ip"`
		Data models.WhitelistEntry `json:"data"`
	}
	list := make([]item, 0, len(ips))
	for ip, data := range ips {
		list = append(list, item{IP: ip, Data: data})
	}
	c.JSON(http.StatusOK, list)
}

func (h *APIHandler) RawIPs(c *gin.Context) {
	ips, _ := h.redisRepo.GetBlockedIPs()
	out := ""
	for ip := range ips {
		out += ip + "\n"
	}
	c.String(http.StatusOK, out)
}

func (h *APIHandler) JSONIPs(c *gin.Context) {
	ips, _ := h.redisRepo.GetBlockedIPs()
	list := []string{}
	for ip := range ips {
		list = append(list, ip)
	}
	c.JSON(http.StatusOK, list)
}

func (h *APIHandler) GetIPDetails(c *gin.Context) {
	ip := c.Param("ip")

	entry, _ := h.redisRepo.GetIPEntry(ip)
	history, _ := h.pgRepo.GetIPHistory(ip)

	c.JSON(http.StatusOK, gin.H{
		"ip":      ip,
		"current": entry,
		"history": history,
	})
}

// IPsPaginated provides server-side pagination and search across all records.
// Query params: limit (int), cursor (opaque string), query (string)
// Response: { items: [{ip, data}], next: "cursor", total: N }
func (h *APIHandler) IPsPaginated(c *gin.Context) {
	limit := 500
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	q := strings.TrimSpace(c.Query("query"))
	cursor := c.Query("cursor")
	country := strings.TrimSpace(c.Query("country"))
	addedBy := strings.TrimSpace(c.Query("added_by"))
	from := strings.TrimSpace(c.Query("from"))
	to := strings.TrimSpace(c.Query("to"))
	items, next, total, err := h.ipService.ListIPsPaginatedAdvanced(c.Request.Context(), limit, cursor, q, country, addedBy, from, to)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "pagination error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "next": next, "total": total})
}

func (h *APIHandler) ExportIPs(c *gin.Context) {
	format := c.DefaultQuery("format", "csv")
	q := strings.TrimSpace(c.Query("query"))
	country := strings.TrimSpace(c.Query("country"))
	addedBy := strings.TrimSpace(c.Query("added_by"))
	from := strings.TrimSpace(c.Query("from"))
	to := strings.TrimSpace(c.Query("to"))

	items, err := h.ipService.ExportIPs(c.Request.Context(), q, country, addedBy, from, to)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "export error"})
		return
	}

	filename := fmt.Sprintf("blocklist_export_%s.%s", time.Now().Format("20060102_150405"), format)

	if format == "ndjson" {
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		c.Header("Content-Type", "application/x-ndjson")
		for _, item := range items {
			line, _ := json.Marshal(item)
			_, _ = c.Writer.Write(line)
			_, _ = c.Writer.Write([]byte("\n"))
		}
		return
	}

	// Default to CSV
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "text/csv")

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	// Header
	_ = writer.Write([]string{"IP", "Timestamp", "Reason", "AddedBy", "Country", "City", "Lat", "Lon"})

	for _, item := range items {
		ip := item["ip"].(string)
		data := item["data"].(*models.IPEntry)

		countryCode := ""
		city := ""
		lat := ""
		lon := ""
		if data.Geolocation != nil {
			countryCode = data.Geolocation.Country
			city = data.Geolocation.City
			lat = fmt.Sprintf("%f", data.Geolocation.Latitude)
			lon = fmt.Sprintf("%f", data.Geolocation.Longitude)
		}

		_ = writer.Write([]string{
			ip,
			data.Timestamp,
			data.Reason,
			data.AddedBy,
			countryCode,
			city,
			lat,
			lon,
		})
	}
}

// Stats returns hour/day/total and top countries.
func (h *APIHandler) Ready(c *gin.Context) {
	dep := map[string]interface{}{"redis": true, "geoip": "unknown"}
	if h.redisRepo != nil {
		if _, err := h.redisRepo.HGetAllRaw("ips"); err != nil {
			dep["redis"] = false
		}
	} else {
		dep["redis"] = false
	}
	c.JSON(http.StatusOK, gin.H{"status": "READY", "dependencies": dep})
}

// Minimal OpenAPI spec
func (h *APIHandler) OpenAPI(c *gin.Context) {
	spec := gin.H{
		"openapi": "3.0.1",
		"info": gin.H{
			"title":       "Blocklist API",
			"description": "API for managing and monitoring blocked IP addresses with GeoIP enrichment and real-time updates.",
			"version":     "1.0.0",
		},
		"servers": []gin.H{
			{"url": "/"},
		},
		"components": gin.H{
			"securitySchemes": gin.H{
				"BearerAuth": gin.H{
					"type":   "http",
					"scheme": "bearer",
				},
			},
			"schemas": gin.H{
				"IPEntry": gin.H{
					"type": "object",
					"properties": gin.H{
						"timestamp": gin.H{"type": "string", "format": "date-time"},
						"reason":    gin.H{"type": "string"},
						"added_by":  gin.H{"type": "string"},
						"geolocation": gin.H{
							"type": "object",
							"properties": gin.H{
								"country":   gin.H{"type": "string"},
								"city":      gin.H{"type": "string"},
								"latitude":  gin.H{"type": "number"},
								"longitude": gin.H{"type": "number"},
							},
						},
					},
				},
				"IPListItem": gin.H{
					"type": "object",
					"properties": gin.H{
						"ip":   gin.H{"type": "string"},
						"data": gin.H{"$ref": "#/components/schemas/IPEntry"},
					},
				},
				"Stats": gin.H{
					"type": "object",
					"properties": gin.H{
						"hour":          gin.H{"type": "integer"},
						"day":           gin.H{"type": "integer"},
						"total":         gin.H{"type": "integer", "description": "Persistent total bans ever recorded"},
						"active_blocks": gin.H{"type": "integer", "description": "Currently active blocks in system"},
						"top_countries": gin.H{
							"type": "array",
							"items": gin.H{
								"type": "object",
								"properties": gin.H{
									"country": gin.H{"type": "string"},
									"count":   gin.H{"type": "integer"},
								},
							},
						},
					},
				},
			},
		},
		"security": []gin.H{
			{"BearerAuth": []string{}},
		},
		"paths": gin.H{
			"/api/v1/ips": gin.H{
				"get": gin.H{
					"summary":  "List blocked IPs with advanced filtering",
					"tags":     []string{"Data Retrieval"},
					"security": []gin.H{{"BearerAuth": []string{}}},
					"parameters": []gin.H{
						{"name": "limit", "in": "query", "description": "Number of records to return", "schema": gin.H{"type": "integer", "default": 500}},
						{"name": "cursor", "in": "query", "description": "Pagination cursor (timestamp score)", "schema": gin.H{"type": "string"}},
						{"name": "query", "in": "query", "description": "Text search across IP, reason, etc.", "schema": gin.H{"type": "string"}},
						{"name": "country", "in": "query", "description": "Filter by ISO country code", "schema": gin.H{"type": "string"}},
						{"name": "added_by", "in": "query", "description": "Filter by who added the block", "schema": gin.H{"type": "string"}},
						{"name": "from", "in": "query", "description": "Filter by start date (ISO8601)", "schema": gin.H{"type": "string", "format": "date-time"}},
						{"name": "to", "in": "query", "description": "Filter by end date (ISO8601)", "schema": gin.H{"type": "string", "format": "date-time"}},
					},
					"responses": gin.H{
						"200": gin.H{
							"description": "A list of blocked IPs",
							"content": gin.H{
								"application/json": gin.H{
									"schema": gin.H{
										"type": "object",
										"properties": gin.H{
											"items": gin.H{"type": "array", "items": gin.H{"$ref": "#/components/schemas/IPListItem"}},
											"next":  gin.H{"type": "string"},
											"total": gin.H{"type": "integer"},
										},
									},
								},
							},
						},
					},
				},
			},
			"/api/v1/ips_list": gin.H{
				"get": gin.H{
					"summary":  "Get simple JSON array of all blocked IPs",
					"tags":     []string{"Data Retrieval"},
					"security": []gin.H{{"BearerAuth": []string{}}},
					"responses": gin.H{
						"200": gin.H{
							"description": "Simple list of IPs",
							"content": gin.H{
								"application/json": gin.H{
									"schema": gin.H{"type": "array", "items": gin.H{"type": "string"}},
								},
							},
						},
					},
				},
			},
			"/api/v1/raw": gin.H{
				"get": gin.H{
					"summary":  "Get plain-text list of blocked IPs",
					"tags":     []string{"Data Retrieval"},
					"security": []gin.H{{"BearerAuth": []string{}}},
					"responses": gin.H{
						"200": gin.H{
							"description": "Newline-separated list of IPs",
							"content":     gin.H{"text/plain": gin.H{"schema": gin.H{"type": "string"}}},
						},
					},
				},
			},
			"/api/v1/stats": gin.H{
				"get": gin.H{
					"summary":  "Get aggregate blocking statistics",
					"tags":     []string{"Monitoring"},
					"security": []gin.H{{"BearerAuth": []string{}}},
					"responses": gin.H{
						"200": gin.H{
							"description": "Statistics object",
							"content": gin.H{
								"application/json": gin.H{"schema": gin.H{"$ref": "#/components/schemas/Stats"}},
							},
						},
					},
				},
			},
			"/api/v1/webhook": gin.H{
				"post": gin.H{
					"summary":     "Perform Enforcement Action (Ban/Unban/Whitelist)",
					"description": "Unified endpoint for all automated actions. Requires a Bearer Token.",
					"tags":        []string{"Enforcement"},
					"security":    []gin.H{{"BearerAuth": []string{}}},
					"requestBody": gin.H{
						"required": true,
						"content": gin.H{
							"application/json": gin.H{
								"schema": gin.H{
									"type": "object",
									"properties": gin.H{
										"ip":      gin.H{"type": "string", "example": "1.2.3.4", "description": "IPv4 or IPv6 address. Optional for 'whitelist' (defaults to caller IP)."},
										"act":     gin.H{"type": "string", "enum": []string{"ban", "unban", "whitelist"}, "description": "Action to perform"},
										"reason":  gin.H{"type": "string", "example": "Brute force attack", "description": "Reason for the action"},
										"ttl":     gin.H{"type": "integer", "example": 86400, "description": "Time-to-live in seconds (ephemeral blocks only)"},
										"persist": gin.H{"type": "boolean", "default": false, "description": "If true, IP is stored in the database indefinitely"},
									},
									"required": []string{"act"},
								},
							},
						},
					},
					"responses": gin.H{
						"200": gin.H{"description": "Action successfully performed"},
						"400": gin.H{"description": "Invalid IP format or missing parameters"},
						"401": gin.H{"description": "Unauthorized"},
						"403": gin.H{"description": "Forbidden - Insufficient permissions"},
					},
				},
			},
		},
	}
	c.JSON(http.StatusOK, spec)
}

func (h *APIHandler) Stats(c *gin.Context) {
	hour, day, totalEver, activeBlocks, top, topASN, topReason, wh, lb, bm, err := h.ipService.Stats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stats error"})
		return
	}

	// shape to match frontend expectations
	tops := make([]gin.H, 0, len(top))
	for i, t := range top {
		if i >= 3 {
			break
		}
		tops = append(tops, gin.H{"country": t.Country, "count": t.Count})
	}

	asns := make([]gin.H, 0, len(topASN))
	for i, a := range topASN {
		if i >= 3 {
			break
		}
		asns = append(asns, gin.H{"asn": a.ASN, "asn_org": a.ASNOrg, "count": a.Count})
	}

	reasons := make([]gin.H, 0, len(topReason))
	for i, r := range topReason {
		if i >= 3 {
			break
		}
		reasons = append(reasons, gin.H{"reason": r.Reason, "count": r.Count})
	}

	c.JSON(http.StatusOK, gin.H{
		"hour":          hour,
		"day":           day,
		"total":         totalEver,
		"active_blocks": activeBlocks,
		"top_countries": tops,
		"top_asns":      asns,
		"top_reasons":   reasons,
		"webhooks_hour": wh,
		"last_block_ts": lb,
		"blocks_minute": bm,
	})
}

func (h *APIHandler) Settings(c *gin.Context) {
	username, _ := c.Get("username")
	webhooks, _ := h.pgRepo.GetActiveWebhooks()
	tokens, _ := h.pgRepo.GetAPITokens(username.(string))

	userPerms, _ := c.Get("permissions")
	hasGlobalTokensPerm := false
	for _, p := range strings.Split(userPerms.(string), ",") {
		if strings.TrimSpace(p) == "manage_global_tokens" {
			hasGlobalTokensPerm = true
			break
		}
	}

	var allTokens []models.APIToken
	if hasGlobalTokensPerm {
		allTokens, _ = h.pgRepo.GetAllAPITokens()
	}

	// Get base URL from request
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, c.Request.Host)

	h.renderHTML(c, http.StatusOK, "settings.html", gin.H{
		"webhooks":             webhooks,
		"tokens":               tokens,
		"all_tokens":           allTokens,
		"admin_username":       h.cfg.GUIAdmin,
		"base_url":             baseURL,
		"username":             username,
		"permissions":          userPerms,
		"manage_global_tokens": hasGlobalTokensPerm,
	})
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

	// Generate random token
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s-%s-%d", username.(string), name, time.Now().UnixNano())))
	rawTokenStr := hex.EncodeToString(hash.Sum(nil))

	token := models.APIToken{
		TokenHash:   rawTokenStr,
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

func (h *APIHandler) AddOutboundWebhook(c *gin.Context) {
	var wh models.OutboundWebhook
	wh.URL = c.PostForm("url")
	wh.Secret = c.PostForm("secret")
	wh.Events = c.PostForm("events")
	wh.GeoFilter = c.PostForm("geo_filter")
	wh.Active = true

	err := h.pgRepo.CreateOutboundWebhook(wh)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to add webhook")
		return
	}

	// Return table row for HTMX
	h.renderHTML(c, http.StatusOK, "settings.html", gin.H{"webhooks": []models.OutboundWebhook{wh}})
}

func (h *APIHandler) DeleteOutboundWebhook(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	_ = h.pgRepo.DeleteOutboundWebhook(id)
	c.Status(http.StatusOK)
}
