package api

import (
	"blocklist/internal/config"
	"blocklist/internal/metrics"
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"blocklist/internal/service"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	zlog "github.com/rs/zerolog/log"
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

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
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

	// API Versioning (Improvement 5)
	v1 := r.Group("/api/v1")
	{
		v1.GET("/raw", h.RawIPs) // Public
	}

	v1auth := v1.Group("/")
	v1auth.Use(h.AuthMiddleware())
	{
		// Webhooks require webhook_access and specific limiter
		v1auth.POST("/webhook", h.webhookLimiter, h.PermissionMiddleware("webhook_access"), h.Webhook)
		v1auth.POST("/webhook2_whitelist", h.webhookLimiter, h.PermissionMiddleware("webhook_access"), h.Webhook2)
		
		// Data viewing requires view_ips and main limiter
		v1auth.GET("/ips", h.mainLimiter, h.PermissionMiddleware("view_ips"), h.IPsPaginated)
		v1auth.GET("/ips_automate", h.mainLimiter, h.PermissionMiddleware("view_ips"), h.AutomateIPs)
		
		// Exports require export_data
		v1auth.GET("/ips/export", h.mainLimiter, h.PermissionMiddleware("export_data"), h.ExportIPs)
		
		// Stats require view_stats
		v1auth.GET("/stats", h.mainLimiter, h.PermissionMiddleware("view_stats"), h.Stats)
	}
	r.GET("/openapi.json", h.OpenAPI)

	// Protected UI routes
	auth := r.Group("/")
	auth.Use(h.AuthMiddleware())
	auth.Use(h.mainLimiter)
	{
		// Dashboard requires view_ips and view_stats
		auth.GET("/dashboard", h.PermissionMiddleware("view_ips"), h.Dashboard)
		auth.GET("/dashboard/table", h.PermissionMiddleware("view_ips"), h.DashboardTable) // For HTMX polling
		
		auth.GET("/api/v1/views", h.PermissionMiddleware("view_ips"), h.GetSavedViews)
		auth.POST("/api/v1/views", h.PermissionMiddleware("view_ips"), h.CreateSavedView)
		auth.DELETE("/api/v1/views/:id", h.PermissionMiddleware("view_ips"), h.DeleteSavedView)

		auth.GET("/settings", h.PermissionMiddleware("manage_webhooks"), h.Settings)
		auth.POST("/api/v1/settings/webhooks", h.PermissionMiddleware("manage_webhooks"), h.AddOutboundWebhook)
		auth.DELETE("/api/v1/settings/webhooks/:id", h.PermissionMiddleware("manage_webhooks"), h.DeleteOutboundWebhook)

		// Enforcement actions
		auth.POST("/block", h.PermissionMiddleware("block_ips"), h.BlockIP)
		auth.POST("/unblock", h.PermissionMiddleware("unblock_ips"), h.UnblockIP)
		auth.POST("/bulk_block", h.PermissionMiddleware("block_ips"), h.BulkBlock)
		auth.POST("/bulk_unblock", h.PermissionMiddleware("unblock_ips"), h.BulkUnblock)
		
		// Whitelist management
		auth.GET("/whitelist", h.PermissionMiddleware("manage_whitelist"), h.Whitelist)
		auth.POST("/add_whitelist", h.PermissionMiddleware("manage_whitelist"), h.AddWhitelist)
		auth.POST("/remove_whitelist", h.PermissionMiddleware("manage_whitelist"), h.RemoveWhitelist)

		// Admin management
		admin := auth.Group("/admin_management")
		admin.Use(h.PermissionMiddleware("manage_admins"))
		{
			admin.GET("", h.AdminManagement)
			admin.POST("/create", h.CreateAdmin)
			admin.POST("/delete", h.DeleteAdmin)
			admin.POST("/change_password", h.ChangeAdminPassword)
			admin.POST("/change_totp", h.ChangeAdminTOTP)
			admin.POST("/change_permissions", h.ChangeAdminPermissions)
			admin.GET("/get_qr/:username", h.GetQR)
		}
	}

	// Legacy / Compatibility routes
	r.POST("/webhook", h.AuthMiddleware(), h.webhookLimiter, h.PermissionMiddleware("webhook_access"), h.Webhook)
	r.GET("/raw", h.RawIPs) // Public
	r.GET("/ips", h.AuthMiddleware(), h.mainLimiter, h.PermissionMiddleware("view_ips"), h.JSONIPs)
	r.GET("/ips_automate", h.AuthMiddleware(), h.mainLimiter, h.PermissionMiddleware("view_ips"), h.AutomateIPs)
	r.GET("/api/ips", h.AuthMiddleware(), h.mainLimiter, h.PermissionMiddleware("view_ips"), h.IPsPaginated)
	r.GET("/api/stats", h.AuthMiddleware(), h.mainLimiter, h.PermissionMiddleware("view_stats"), h.Stats)
	r.GET("/health", h.Health)
	r.GET("/ready", h.Ready)
	r.GET("/metrics", h.MetricsAuthMiddleware(), gin.WrapH(promhttp.Handler()))
}

// Improvement 3: Cache persistent blocks in Redis
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

func (h *APIHandler) Dashboard(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username").(string)

	ips := h.getCombinedIPs()

	// Preload stats for initial render
	hour, day, total, top, topASN, topReason, _ := h.ipService.Stats(c.Request.Context())
	
	tops := make([]map[string]interface{}, 0, len(top))
	for _, t := range top { tops = append(tops, map[string]interface{}{"Country": t.Country, "Count": t.Count}) }

	asns := make([]map[string]interface{}, 0, len(topASN))
	for _, a := range topASN { asns = append(asns, map[string]interface{}{"ASN": a.ASN, "ASNOrg": a.ASNOrg, "Count": a.Count}) }

	reasons := make([]map[string]interface{}, 0, len(topReason))
	for _, r := range topReason { reasons = append(reasons, map[string]interface{}{"Reason": r.Reason, "Count": r.Count}) }

	views, _ := h.pgRepo.GetSavedViews(username)

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"ips":            ips,
		"total_ips":      len(ips),
		"admin_username": h.cfg.GUIAdmin,
		"username":       username,
		"views":          views,
		"stats": gin.H{
			"hour":          hour,
			"day":           day,
			"total":         total,
			"top_countries": tops,
			"top_asns":      asns,
			"top_reasons":   reasons,
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
	c.HTML(http.StatusOK, "dashboard_table.html", gin.H{
		"ips": ips,
	})
}

func (h *APIHandler) Health(c *gin.Context) {
	status := "UP"
	dbStatus := "OK"
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
	}
	c.JSON(200, gin.H{"status": status, "postgres": dbStatus, "redis": redisStatus})
}

func (h *APIHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for Bearer token first
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			// In a real app, we'd hash the token and check against DB
			// For now, let's assume token is the hash for simplicity of the scaffolding
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
				_ = h.pgRepo.UpdateTokenLastUsed(token.ID)
				c.Set("username", token.Username)
				c.Set("role", token.Role)
				c.Next()
				return
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
		c.Set("username", username)
		
		// Get role and permissions from DB or session
		role := session.Get("role")
		perms := session.Get("permissions")
		if role == nil || perms == nil {
			admin, _ := h.pgRepo.GetAdmin(username)
			if admin != nil {
				role = admin.Role
				perms = admin.Permissions
				session.Set("role", role)
				session.Set("permissions", perms)
				_ = session.Save()
			} else {
				role = "viewer"
				perms = "gui_read"
			}
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

func (h *APIHandler) PermissionMiddleware(requiredPerm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		perms, exists := c.Get("permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permissions not found"})
			c.Abort()
			return
		}

		permStr := perms.(string)
		
		// System admin bypass (except for webhook_access by default)
		username, _ := c.Get("username")
		if username == h.cfg.GUIAdmin && requiredPerm != "webhook_access" {
			c.Next()
			return
		}

		userPerms := strings.Split(permStr, ",")
		hasPerm := false
		for _, p := range userPerms {
			if strings.TrimSpace(p) == requiredPerm {
				hasPerm = true
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
	c.HTML(http.StatusOK, "login.html", nil)
}

func (h *APIHandler) VerifyFirstFactor(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	admin, err := h.pgRepo.GetAdmin(username)
	if err != nil {
		c.HTML(http.StatusOK, "login_error.html", gin.H{"error": "Invalid Operator ID"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
	if err != nil {
		c.HTML(http.StatusOK, "login_error.html", gin.H{"error": "Access Denied"})
		return
	}

	// Success: Return TOTP field via HTMX
	c.HTML(http.StatusOK, "login_totp_step.html", gin.H{
		"username": username,
		"password": password,
	})
}

func (h *APIHandler) Login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	totpCode := c.PostForm("totp")
	if h.authService.CheckAuth(username, password, totpCode) {
		session := sessions.Default(c)
		session.Set("logged_in", true)
		session.Set("username", username)
		session.Set("client_ip", c.ClientIP())
		session.Set("login_time", time.Now().UTC().Format(time.RFC3339))
		admin, _ := h.pgRepo.GetAdmin(username)
		if admin != nil {
			session.Set("role", admin.Role)
			session.Set("permissions", admin.Permissions)
		}
		if err := session.Save(); err != nil {
			zlog.Error().Err(err).Msg("Failed to save session during login")
		}
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}
	c.HTML(http.StatusOK, "login.html", gin.H{
		"error":    "Invalid credentials or TOTP code",
		"username": username,
		"password": password,
		"step":     "totp",
	})
}

func (h *APIHandler) Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	_ = session.Save()
	c.Redirect(http.StatusFound, "/login")
}

func (h *APIHandler) BlockIP(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username").(string)

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
		AddedBy:     username,
		TTL:         req.TTL,
		ExpiresAt:   expiresAt,
	}

	if req.Persist && h.pgRepo != nil {
		_ = h.pgRepo.CreatePersistentBlock(req.IP, entry)
		_ = h.pgRepo.LogAction(username, "BLOCK_PERSISTENT", req.IP, req.Reason)
	} else {
		_ = h.redisRepo.BlockIP(req.IP, entry)
		if h.pgRepo != nil {
			_ = h.pgRepo.LogAction(username, "BLOCK_EPHEMERAL", req.IP, req.Reason)
		}
	}
	// stats + index (non-persistent tracked in Redis)
	if country := func() string { if geo!=nil { return geo.Country }; return "" }(); true {
		_ = h.redisRepo.IndexIPTimestamp(req.IP, now)
		_ = h.redisRepo.IncrTotal(1)
		_ = h.redisRepo.IncrCountry(country, 1)
		_ = h.redisRepo.IncrHourBucket(now, 1)
		_ = h.redisRepo.IncrDayBucket(now, 1)
		_ = h.redisRepo.IncrReason(entry.Reason, 1)
		if geo != nil && geo.ASN != 0 {
			_ = h.redisRepo.IncrASN(geo.ASN, geo.ASNOrg, 1)
		}
	}
	metrics.MetricBlocksTotal.WithLabelValues("gui").Inc()

	h.hub.BroadcastEvent("block", map[string]interface{}{
		"ip":   req.IP,
		"data": entry,
	})
	h.webhookService.Notify(c.Request.Context(), "block", map[string]interface{}{"ip": req.IP, "data": entry})

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) UnblockIP(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username").(string)

	var req struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error"})
		return
	}

	_ = h.redisRepo.UnblockIP(req.IP)
	if h.pgRepo != nil {
		_ = h.pgRepo.DeletePersistentBlock(req.IP)
		_ = h.pgRepo.LogAction(username, "UNBLOCK", req.IP, "")
	}
	// decrement counters where applicable
	if e, err := h.redisRepo.GetIPEntry(req.IP); err == nil && e != nil {
		cc := ""
		if e.Geolocation != nil { cc = e.Geolocation.Country }
		_ = h.redisRepo.IncrTotal(-1)
		_ = h.redisRepo.IncrCountry(cc, -1)
		_ = h.redisRepo.RemoveIPTimestamp(req.IP)
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

	err := h.ipService.BulkBlock(c.Request.Context(), req.IPs, req.Reason, username.(string), req.Persist, req.TTL)
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

	c.HTML(http.StatusOK, "whitelist.html", gin.H{
		"whitelisted_ips": ips,
		"blocked_subnets": subnets,
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
	c.JSON(200, gin.H{"status": "success"})
}

func (h *APIHandler) verifyHMAC(body []byte, signature string) bool {
	if h.cfg.WebhookSecret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(h.cfg.WebhookSecret))
	mac.Write(body)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

func (h *APIHandler) Webhook(c *gin.Context) {
	// Read body for HMAC verification
	body, _ := io.ReadAll(c.Request.Body)
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	signature := c.GetHeader("X-Webhook-Signature")
	authenticated := false

	if signature != "" && h.cfg.WebhookSecret != "" {
		if h.verifyHMAC(body, signature) {
			authenticated = true
		}
	}

	var data struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Act      string `json:"act"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(400, gin.H{"status": "invalid request"})
		return
	}

	if !authenticated {
		if h.pgRepo != nil {
			// Verify against database user permissions
			admin, err := h.pgRepo.GetAdmin(data.Username)
			if err != nil || admin == nil {
				c.JSON(401, gin.H{"error": "Unauthorized user"})
				return
			}
			if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(data.Password)); err != nil {
				c.JSON(401, gin.H{"error": "Invalid credentials"})
				return
			}
			// Check for webhook_access permission
			if !strings.Contains(admin.Permissions, "webhook_access") {
				c.JSON(403, gin.H{"error": "Webhook access denied for this user"})
				return
			}
		} else {
			// Database unavailable, fallback to hardcoded GUIAdmin config
			if data.Username != h.cfg.GUIAdmin || data.Password != h.cfg.GUIPassword {
				c.JSON(401, gin.H{"error": "Unauthorized (Database Offline)"})
				return
			}
		}
	}

	if data.IP == "" || !h.ipService.IsValidIP(data.IP) {
		c.JSON(400, gin.H{"status": "invalid IP"})
		return
	}

	timestamp := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	geo := h.ipService.GetGeoIP(data.IP)
	now := time.Now().UTC()
	entry := models.IPEntry{
		Timestamp:   timestamp,
		Geolocation: geo,
		Reason:      data.Reason,
		AddedBy:     "Webhook",
	}

	if data.Act == "ban" || data.Act == "ban-ip" {
		_ = h.redisRepo.BlockIP(data.IP, entry)
		_ = h.redisRepo.IndexIPTimestamp(data.IP, now)
		_ = h.redisRepo.IncrTotal(1)
		cc := ""
		if geo != nil { cc = geo.Country }
		_ = h.redisRepo.IncrCountry(cc, 1)
		_ = h.redisRepo.IncrHourBucket(now, 1)
		_ = h.redisRepo.IncrDayBucket(now, 1)
		metrics.MetricBlocksTotal.WithLabelValues("webhook").Inc()
		h.hub.BroadcastEvent("block", map[string]interface{}{
			"ip":   data.IP,
			"data": entry,
		})
		c.JSON(200, gin.H{"status": "IP banned", "ip": data.IP})
	} else if data.Act == "unban" || data.Act == "delete-ban" {
		_ = h.redisRepo.UnblockIP(data.IP)
		// adjust counters if present
		if e, err := h.redisRepo.GetIPEntry(data.IP); err == nil && e != nil {
			cc := ""
			if e.Geolocation != nil { cc = e.Geolocation.Country }
			_ = h.redisRepo.IncrTotal(-1)
			_ = h.redisRepo.IncrCountry(cc, -1)
			_ = h.redisRepo.RemoveIPTimestamp(data.IP)
		}
		metrics.MetricUnblocksTotal.WithLabelValues("webhook").Inc()
		c.JSON(200, gin.H{"status": "IP unbanned", "ip": data.IP})
	} else {
		c.JSON(501, gin.H{"status": "action not implemented"})
	}
}

func (h *APIHandler) Webhook2(c *gin.Context) {
	// automated whitelist for the calling IP
	clientIP := c.ClientIP()
	geo := h.ipService.GetGeoIP(clientIP)
	entry := models.WhitelistEntry{
		Timestamp:   time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Geolocation: geo,
		AddedBy:     "WebhookAuto",
		Reason:      "Automated Whitelist",
	}
	_ = h.redisRepo.WhitelistIP(clientIP, entry)
	c.JSON(http.StatusOK, gin.H{"status": "IP added", "ip": clientIP})
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

	if req.Role == "" { req.Role = "operator" }
	if req.Permissions == "" { req.Permissions = "gui_read" }

	admin, err := h.authService.CreateAdmin(req.Username, req.Password, req.Role, req.Permissions)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "success", "username": admin.Username})
}

func (h *APIHandler) ChangeAdminPermissions(c *gin.Context) {
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

	err := h.pgRepo.UpdateAdminPermissions(req.Username, req.Permissions)
	if err != nil {
		c.JSON(500, gin.H{"error": "database error"})
		return
	}

	c.JSON(200, gin.H{"status": "success"})
}

func (h *APIHandler) AdminManagement(c *gin.Context) {
	admins, _ := h.pgRepo.GetAllAdmins()
	adminMap := make(map[string]models.AdminAccount)
	for _, a := range admins {
		adminMap[a.Username] = a
	}
	c.HTML(http.StatusOK, "admin_management.html", gin.H{
		"admins": adminMap,
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

	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "Blocklist App",
		AccountName: req.Username,
	})

	_ = h.pgRepo.UpdateAdminToken(req.Username, key.Secret())

	var png []byte
	png, _ = qrcode.Encode(key.URL(), qrcode.Medium, 256)
	imgBase64 := base64.StdEncoding.EncodeToString(png)

	c.JSON(200, gin.H{"status": "success", "qr_image": "data:image/png;base64," + imgBase64})
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
	png, _ := qrcode.Encode(url, qrcode.Medium, 256)
	c.Data(200, "image/png", png)
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

// IPsPaginated provides server-side pagination and search across all records.
// Query params: limit (int), cursor (opaque string), query (string)
// Response: { items: [{ip, data}], next: "cursor", total: N }
func (h *APIHandler) IPsPaginated(c *gin.Context) {
	limit := 500
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 { limit = n }
	}
	q := strings.TrimSpace(c.Query("query"))
	cursor := c.Query("cursor")
	country := strings.TrimSpace(c.Query("country"))
	addedBy := strings.TrimSpace(c.Query("added_by"))
	from := strings.TrimSpace(c.Query("from"))
	to := strings.TrimSpace(c.Query("to"))
	items, next, total, err := h.ipService.ListIPsPaginatedAdvanced(c.Request.Context(), limit, cursor, q, country, addedBy, from, to)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": "pagination error"}); return }
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
func (h *APIHandler) AutomateIPs(c *gin.Context) {
	var ips []string
	err := h.redisRepo.GetCache("cached_ips_automate", &ips)
	if err != nil {
		// Fallback to all raw IPs if cache is empty
		combined := h.getCombinedIPs()
		ips = make([]string, 0, len(combined))
		for ip := range combined {
			ips = append(ips, ip)
		}
	}
	c.JSON(http.StatusOK, ips)
}

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
            "title": "Blocklist API",
            "description": "API for managing and monitoring blocked IP addresses with GeoIP enrichment and real-time updates.",
            "version": "1.0.0",
        },
        "servers": []gin.H{
            {"url": "/"},
        },
        "components": gin.H{
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
                        "hour":  gin.H{"type": "integer"},
                        "day":   gin.H{"type": "integer"},
                        "total": gin.H{"type": "integer"},
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
        "paths": gin.H{
            "/api/v1/ips": gin.H{
                "get": gin.H{
                    "summary": "List blocked IPs with advanced filtering",
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
            "/api/v1/stats": gin.H{
                "get": gin.H{
                    "summary": "Get aggregate blocking statistics",
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
            "/webhook": gin.H{
                "post": gin.H{
                    "summary": "Automated ban/unban endpoint",
                    "requestBody": gin.H{
                        "required": true,
                        "content": gin.H{
                            "application/json": gin.H{
                                "schema": gin.H{
                                    "type": "object",
                                    "properties": gin.H{
                                        "ip":       gin.H{"type": "string"},
                                        "reason":   gin.H{"type": "string"},
                                        "act":      gin.H{"type": "string", "enum": []string{"ban", "unban"}},
                                        "username": gin.H{"type": "string"},
                                        "password": gin.H{"type": "string"},
                                    },
                                    "required": []string{"ip", "act", "username", "password"},
                                },
                            },
                        },
                    },
                    "responses": gin.H{"200": gin.H{"description": "Action performed"}},
                },
            },
        },
    }
    c.JSON(http.StatusOK, spec)
}

func (h *APIHandler) Stats(c *gin.Context) {
	hour, day, total, top, topASN, topReason, err := h.ipService.Stats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stats error"})
		return
	}
	
	// shape to match frontend expectations
	tops := make([]gin.H, 0, len(top))
	for i, t := range top {
		if i >= 3 { break }
		tops = append(tops, gin.H{"country": t.Country, "count": t.Count})
	}

	asns := make([]gin.H, 0, len(topASN))
	for i, a := range topASN {
		if i >= 3 { break }
		asns = append(asns, gin.H{"asn": a.ASN, "asn_org": a.ASNOrg, "count": a.Count})
	}

	reasons := make([]gin.H, 0, len(topReason))
	for i, r := range topReason {
		if i >= 3 { break }
		reasons = append(reasons, gin.H{"reason": r.Reason, "count": r.Count})
	}

	c.JSON(http.StatusOK, gin.H{
		"hour":          hour,
		"day":           day,
		"total":         total,
		"top_countries": tops,
		"top_asns":      asns,
		"top_reasons":   reasons,
	})
}

func (h *APIHandler) Settings(c *gin.Context) {
	webhooks, _ := h.pgRepo.GetActiveWebhooks()
	
	// Get base URL from request
	scheme := "http"
	if c.Request.TLS != nil { scheme = "https" }
	baseURL := fmt.Sprintf("%s://%s", scheme, c.Request.Host)

	c.HTML(http.StatusOK, "settings.html", gin.H{
		"webhooks":   webhooks,
		"admin_user": h.cfg.GUIAdmin,
		"base_url":   baseURL,
	})
}

func (h *APIHandler) AddOutboundWebhook(c *gin.Context) {
	var wh models.OutboundWebhook
	wh.URL = c.PostForm("url")
	wh.Secret = c.PostForm("secret")
	wh.Events = c.PostForm("events")
	wh.Active = true

	err := h.pgRepo.CreateOutboundWebhook(wh)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to add webhook")
		return
	}

	// Return table row for HTMX
	c.HTML(http.StatusOK, "settings.html", gin.H{"webhooks": []models.OutboundWebhook{wh}})
	// Actually we should return just the row fragment, but for now this is ok if htmx targets correctly
	// Better: return just the row.
}

func (h *APIHandler) DeleteOutboundWebhook(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	_ = h.pgRepo.DeleteOutboundWebhook(id)
	c.Status(http.StatusOK)
}