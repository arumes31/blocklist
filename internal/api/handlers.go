package api

import (
	"blocklist/internal/config"
	"blocklist/internal/metrics"
	"blocklist/internal/models"
	"blocklist/internal/service"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	zlog "github.com/rs/zerolog/log"
)

type HandlerOptions struct {
	Config                *config.Config
	RedisRepo             RedisRepositoryProvider
	PgRepo                PostgresRepositoryProvider
	AuthService           AuthServiceProvider
	IPService             IPServiceProvider
	Hub                   *Hub
	WebhookService        *service.WebhookService
	ExternalSourceService *service.ExternalSourceService
	MainLimiter           gin.HandlerFunc
	LoginLimiter          gin.HandlerFunc
	WebhookLimiter        gin.HandlerFunc
}

type APIHandler struct {
	cfg                   *config.Config
	redisRepo             RedisRepositoryProvider
	pgRepo                PostgresRepositoryProvider
	authService           AuthServiceProvider
	ipService             IPServiceProvider
	hub                   *Hub
	webhookService        *service.WebhookService
	externalSourceService *service.ExternalSourceService
	mainLimiter           gin.HandlerFunc
	loginLimiter          gin.HandlerFunc
	trustedProxies        []netip.Prefix
	upgrader              websocket.Upgrader
	webhookLimiter        gin.HandlerFunc
}

// NewAPIHandler creates a new instance of APIHandler with the necessary dependencies.
func NewAPIHandler(opts *HandlerOptions) *APIHandler {
	if opts == nil {
		opts = &HandlerOptions{}
	}
	trusted := []string{"127.0.0.1/32", "172.16.0.0/12", "100.64.0.0/10", "10.0.0.0/8", "192.168.0.0/16"}
	if opts.Config != nil && opts.Config.TrustedProxies != "" {
		p := strings.Split(opts.Config.TrustedProxies, ",")
		for i := range p {
			val := strings.TrimSpace(p[i])
			if !strings.Contains(val, "/") {
				val += "/32"
			}
			trusted = append(trusted, val)
		}
	}

	var prefixes []netip.Prefix
	for _, s := range trusted {
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p)
		}
	}

	h := &APIHandler{
		cfg:                   opts.Config,
		redisRepo:             opts.RedisRepo,
		pgRepo:                opts.PgRepo,
		authService:           opts.AuthService,
		ipService:             opts.IPService,
		hub:                   opts.Hub,
		webhookService:        opts.WebhookService,
		externalSourceService: opts.ExternalSourceService,
		mainLimiter:           opts.MainLimiter,
		loginLimiter:          opts.LoginLimiter,
		webhookLimiter:        opts.WebhookLimiter,
		trustedProxies:        prefixes,
	}

	h.upgrader = websocket.Upgrader{
		ReadBufferSize:    1024,
		WriteBufferSize:   1024,
		EnableCompression: true,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}

			requestScheme := "http"
			isTrusted := false
			remoteIPStr, _, _ := net.SplitHostPort(r.RemoteAddr)
			if remoteIPStr == "" {
				remoteIPStr = r.RemoteAddr
			}
			if remoteIP, err := netip.ParseAddr(remoteIPStr); err == nil {
				for _, p := range h.trustedProxies {
					if p.Contains(remoteIP) {
						isTrusted = true
						break
					}
				}
			}

			if r.TLS != nil || (isTrusted && r.Header.Get("X-Forwarded-Proto") == "https") {
				requestScheme = "https"
			}
			return u.Scheme == requestScheme && strings.EqualFold(u.Host, r.Host)
		},
	}

	return h
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

func (h *APIHandler) WS(c *gin.Context) {
	// Require authenticated session
	session := sessions.Default(c)
	if loggedIn := session.Get("logged_in"); loggedIn == nil || !loggedIn.(bool) {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		zlog.Error().Err(err).
			Str("host", c.Request.Host).
			Msg("WebSocket upgrade failed")
		return
	}

	// Wrap the connection so all writes (broadcasts from the Hub and the
	// keep-alive pings below) serialize on a single per-connection mutex;
	// gorilla/websocket does not allow concurrent writers.
	client := &wsClient{conn: conn}
	h.hub.register <- client

	// Keep-alive setup
	pingTicker := time.NewTicker(30 * time.Second)
	defer func() {
		pingTicker.Stop()
		h.hub.unregister <- client
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
			if err := client.writeMessage(websocket.PingMessage, nil); err != nil {
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
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.HasPrefix(target, `/\`) {
		return false
	}
	// Disallow / followed by whitespace, control characters or @
	if len(target) > 1 && (target[1] <= ' ' || target[1] == '@') {
		return false
	}
	return true
}

func (h *APIHandler) validateIP(c *gin.Context, ip string) bool {
	if net.ParseIP(ip) == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP address"})
		return false
	}
	return true
}

func (h *APIHandler) validateIPOrCIDR(c *gin.Context, input string) bool {
	if net.ParseIP(input) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(input)
	if err == nil {
		return true
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP or CIDR"})
	return false
}

// RegisterRoutes sets up all the API and UI routes for the application.
func (h *APIHandler) RegisterRoutes(r *gin.Engine) {
	r.Use(h.PrometheusMiddleware())
	r.Use(h.BlockCheckMiddleware())
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
		v1auth.GET("/whitelists-raw", h.mainLimiter, h.PermissionMiddleware("view_ips"), h.RawWhitelists)
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
		auth.GET("/audit-logs", h.PermissionMiddleware("view_ips"), h.AuditLogExplorer)
		auth.GET("/threat-map", h.PermissionMiddleware("view_ips"), h.ThreatMap)
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

		// Excluded list management (IPs, subnets, or FQDNs that can never be blocked)
		auth.GET("/excluded", h.PermissionMiddleware("manage_excluded"), h.Excluded)
		auth.GET("/api/v1/excluded", h.PermissionMiddleware("manage_excluded"), h.JSONExcluded)
		auth.POST("/add_excluded", h.PermissionMiddleware("manage_excluded"), h.AddExcluded)
		auth.POST("/remove_excluded", h.PermissionMiddleware("manage_excluded"), h.RemoveExcluded)

		// External sources
		auth.POST("/api/v1/excluded/sources", h.PermissionMiddleware("manage_excluded"), h.AddExternalSource)
		auth.DELETE("/api/v1/excluded/sources/:id", h.PermissionMiddleware("manage_excluded"), h.DeleteExternalSource)
		auth.POST("/api/v1/excluded/sources/refresh", h.PermissionMiddleware("manage_excluded"), h.RefreshExternalSource)

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
	ips, err := h.redisRepo.GetBlockedIPs()
	if err != nil {
		zlog.Error().Err(err).Msg("Failed to fetch blocked IPs from Redis")
		ips = make(map[string]models.IPEntry)
	} else if ips == nil {
		ips = make(map[string]models.IPEntry)
	}

	if h.pgRepo != nil {
		var pIps map[string]models.IPEntry
		// Try cache first
		err := h.redisRepo.GetCache("persistent_ips_cache", &pIps)
		if err != nil {
			// Cache miss, fetch from DB
			var pgErr error
			pIps, pgErr = h.pgRepo.GetPersistentBlocks()
			if pgErr != nil {
				zlog.Error().Err(pgErr).Msg("Failed to fetch persistent blocks from Postgres")
			} else {
				// Set cache for 1 minute
				_ = h.redisRepo.SetCache("persistent_ips_cache", pIps, 1*time.Minute)
			}
		}

		for ip, data := range pIps {
			ips[ip] = data
		}
	}
	return ips
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
