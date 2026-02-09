package api

import (
	"blocklist/internal/config"
	"blocklist/internal/metrics"
	"blocklist/internal/models"
	"blocklist/internal/service"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	zlog "github.com/rs/zerolog/log"
)

type APIHandler struct {
	cfg            *config.Config
	redisRepo      RedisRepositoryProvider
	pgRepo         PostgresRepositoryProvider
	authService    AuthServiceProvider
	ipService      IPServiceProvider
	hub            *Hub
	webhookService *service.WebhookService
	mainLimiter    gin.HandlerFunc
	loginLimiter   gin.HandlerFunc
	webhookLimiter gin.HandlerFunc
}

// NewAPIHandler creates a new instance of APIHandler with the necessary dependencies.
func NewAPIHandler(cfg *config.Config, r RedisRepositoryProvider, pg PostgresRepositoryProvider, auth AuthServiceProvider, ip IPServiceProvider, hub *Hub, wh *service.WebhookService) *APIHandler {
	return &APIHandler{
		cfg:            cfg,
		redisRepo:      r,
		pgRepo:         pg,
		authService:    auth,
		ipService:      ip,
		hub:            hub,
		webhookService: wh,
		mainLimiter:    nil, // Initialized in SetLimiters
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
			"/api/v1/whitelists-raw": gin.H{
				"get": gin.H{
					"summary":  "Get plain-text list of whitelisted IPs",
					"tags":     []string{"Data Retrieval"},
					"security": []gin.H{{"BearerAuth": []string{}}},
					"responses": gin.H{
						"200": gin.H{
							"description": "Newline-separated list of whitelisted IPs",
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
										"reason":  gin.H{"type": "string", "example": "Brute force attack", "description": "Reason for the action"},
										"ttl":     gin.H{"type": "integer", "example": 86400, "description": "Time-to-live in seconds (ephemeral blocks only). Defaults to 86400 (24h) for bans if persist is false."},
										"persist": gin.H{"type": "boolean", "default": false, "description": "If true, IP is stored in the database indefinitely"},
									},
									"oneOf": []gin.H{
										{
											"type": "object",
											"properties": gin.H{
												"act": gin.H{"type": "string", "enum": []string{"selfwhitelist"}, "description": "Whitelists the caller's source IP."},
											},
											"required": []string{"act"},
										},
										{
											"type": "object",
											"properties": gin.H{
												"act": gin.H{"type": "string", "enum": []string{"ban", "unban", "whitelist", "ban-ip", "unban-ip"}, "description": "Enforcement action"},
												"ip":  gin.H{"type": "string", "example": "1.2.3.4", "description": "IPv4 or IPv6 address. Required for these actions."},
											},
											"required": []string{"act", "ip"},
										},
									},
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
