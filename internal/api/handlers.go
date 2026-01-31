package api

import (
	"blocklist/internal/config"
	"blocklist/internal/metrics"
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"blocklist/internal/service"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

type APIHandler struct {
	cfg         *config.Config
	redisRepo   *repository.RedisRepository
	pgRepo      *repository.PostgresRepository
	authService *service.AuthService
	ipService   *service.IPService
	hub         *Hub
}

func NewAPIHandler(cfg *config.Config, r *repository.RedisRepository, pg *repository.PostgresRepository, auth *service.AuthService, ip *service.IPService, hub *Hub) *APIHandler {
	return &APIHandler{
		cfg:         cfg,
		redisRepo:   r,
		pgRepo:      pg,
		authService: auth,
		ipService:   ip,
		hub:         hub,
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	EnableCompression: true,
	CheckOrigin: func(r *http.Request) bool {
		// Allow only same-origin WS from our host
		host := r.Host
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser or same-origin without header
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return u.Host == host
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
	defer func() {
		h.hub.unregister <- conn
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
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
	r.GET("/login", h.ShowLogin)
	r.POST("/login", h.Login)
	r.POST("/login/verify", h.VerifyFirstFactor) // New Step
	r.GET("/logout", h.Logout)
	r.GET("/ws", h.WS)

	// API Versioning (Improvement 5)
	v1 := r.Group("/api/v1")
	v1.Use(h.AuthMiddleware())
	{
		v1.POST("/webhook", h.Webhook)
		v1.POST("/webhook2_whitelist", h.Webhook2)
		v1.GET("/raw", h.RawIPs)
		v1.GET("/ips", h.IPsPaginated) // server-side pagination + search
		v1.GET("/stats", h.Stats)       // stats endpoint for dashboard
	}
	// OpenAPI and readiness
	r.GET("/openapi.json", h.OpenAPI)

	// Protected UI routes
	auth := r.Group("/")
	auth.Use(h.AuthMiddleware())
	{
		auth.GET("/dashboard", h.Dashboard)
		auth.GET("/dashboard/table", h.DashboardTable) // For HTMX polling
		
		operator := auth.Group("/")
		operator.Use(h.RBACMiddleware("operator"))
		{
			operator.POST("/block", h.BlockIP)
			operator.POST("/unblock", h.UnblockIP)
			operator.GET("/whitelist", h.Whitelist)
			operator.POST("/add_whitelist", h.AddWhitelist)
			operator.POST("/remove_whitelist", h.RemoveWhitelist)
		}

		// Admin management
		admin := auth.Group("/admin_management")
		admin.Use(h.AdminOnlyMiddleware())
		{
			admin.GET("", h.AdminManagement)
			admin.POST("/create", h.CreateAdmin)
			admin.POST("/delete", h.DeleteAdmin)
			admin.POST("/change_password", h.ChangeAdminPassword)
			admin.POST("/change_totp", h.ChangeAdminTOTP)
			admin.GET("/get_qr/:username", h.GetQR)
		}
	}

	// Legacy / Compatibility routes
	r.POST("/webhook", h.Webhook)
	r.GET("/raw", h.RawIPs)
	r.GET("/ips", h.JSONIPs)
	r.GET("/api/ips", h.IPsPaginated)
	r.GET("/api/stats", h.Stats)
	r.GET("/health", h.Health)
	r.GET("/ready", h.Ready)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
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
			h.redisRepo.SetCache("persistent_ips_cache", pIps, 1*time.Minute)
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
	hour, day, total, top, _ := h.ipService.Stats(c.Request.Context())
	tops := make([]map[string]interface{}, 0, len(top))
	for _, t := range top { tops = append(tops, map[string]interface{}{"Country": t.Country, "Count": t.Count}) }

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"ips":            ips,
		"total_ips":      len(ips),
		"admin_username": h.cfg.GUIAdmin,
		"username":       username,
		"stats":          gin.H{"hour": hour, "day": day, "total": total, "top_countries": tops},
	})
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
	if _, err := h.redisRepo.HGetAllRaw("ips"); err != nil {
		redisStatus = "ERROR"
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
				h.pgRepo.UpdateTokenLastUsed(token.ID)
				c.Set("username", token.Username)
				c.Set("role", token.Role)
				c.Next()
				return
			}
		}

		session := sessions.Default(c)
		if loggedIn := session.Get("logged_in"); loggedIn == nil || !loggedIn.(bool) {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			} else {
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}
		clientIP := c.ClientIP()
		if storedIP := session.Get("client_ip"); storedIP == nil || storedIP.(string) != clientIP {
			session.Clear()
			session.Save()
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		
		username := session.Get("username").(string)
		c.Set("username", username)
		
		// Get role from DB or session
		role := session.Get("role")
		if role == nil {
			admin, _ := h.pgRepo.GetAdmin(username)
			if admin != nil {
				role = admin.Role
				session.Set("role", role)
				session.Save()
			} else {
				role = "viewer"
			}
		}
		c.Set("role", role.(string))
		
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

func (h *APIHandler) AdminOnlyMiddleware() gin.HandlerFunc {
	return h.RBACMiddleware("admin")
}

func (h *APIHandler) ShowLogin(c *gin.Context) {
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
	totp := c.PostForm("totp")
	if h.authService.CheckAuth(username, password, totp) {
		session := sessions.Default(c)
		session.Set("logged_in", true)
		session.Set("username", username)
		session.Set("client_ip", c.ClientIP())
		session.Set("login_time", time.Now().UTC().Format(time.RFC3339))
		session.Save()
		c.Redirect(http.StatusFound, "/dashboard")
		return
	}
	c.HTML(http.StatusOK, "login.html", gin.H{"error": "Invalid credentials"})
}

func (h *APIHandler) Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/login")
}

func (h *APIHandler) BlockIP(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username").(string)

	var req struct {
		IP      string `json:"ip"`
		Persist bool   `json:"persist"`
		Reason  string `json:"reason"`
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
	}

	if req.Persist && h.pgRepo != nil {
		h.pgRepo.CreatePersistentBlock(req.IP, entry)
		h.pgRepo.LogAction(username, "BLOCK_PERSISTENT", req.IP, req.Reason)
	} else {
		h.redisRepo.BlockIP(req.IP, entry)
		if h.pgRepo != nil {
			h.pgRepo.LogAction(username, "BLOCK_EPHEMERAL", req.IP, req.Reason)
		}
	}
	// stats + index (non-persistent tracked in Redis)
	if country := func() string { if geo!=nil { return geo.Country }; return "" }(); true {
		_ = h.redisRepo.IndexIPTimestamp(req.IP, now)
		_ = h.redisRepo.IncrTotal(1)
		_ = h.redisRepo.IncrCountry(country, 1)
		_ = h.redisRepo.IncrHourBucket(now, 1)
		_ = h.redisRepo.IncrDayBucket(now, 1)
	}
	metrics.MetricBlocksTotal.WithLabelValues("gui").Inc()

	h.hub.BroadcastEvent("block", map[string]interface{}{
		"ip":   req.IP,
		"data": entry,
	})

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

	h.redisRepo.UnblockIP(req.IP)
	if h.pgRepo != nil {
		h.pgRepo.DeletePersistentBlock(req.IP)
		h.pgRepo.LogAction(username, "UNBLOCK", req.IP, "")
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

	if c.GetHeader("HX-Request") != "" {
		c.Status(http.StatusOK)
		return
	}

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
	h.redisRepo.WhitelistIP(req.IP, entry)
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
	h.redisRepo.RemoveFromWhitelist(req.IP)
	c.JSON(200, gin.H{"status": "success"})
}

func (h *APIHandler) WebhookAuth(c *gin.Context) bool {
	// Simple Basic Auth or JSON body auth as in Python
	// For now, let's replicate the JSON body auth from app.py
	// simplified for now:
	return true 
}

func (h *APIHandler) Webhook(c *gin.Context) {
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

	// Verify Auth (replicate USERS env var check if needed)
	// For simplicity, checking against GUIAdmin if others not set
	if data.Username != h.cfg.GUIAdmin || data.Password != h.cfg.GUIPassword {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
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
		h.redisRepo.BlockIP(data.IP, entry)
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
		h.redisRepo.UnblockIP(data.IP)
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
	h.redisRepo.WhitelistIP(clientIP, entry)
	c.JSON(http.StatusOK, gin.H{"status": "IP added", "ip": clientIP})
}

func (h *APIHandler) CreateAdmin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	if req.Role == "" { req.Role = "operator" }

	admin, err := h.authService.CreateAdmin(req.Username, req.Password, req.Role)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "success", "username": admin.Username})
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

	h.pgRepo.UpdateAdminToken(req.Username, key.Secret())

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
// Delegate to service/repository: prefer time-ordered ZSET with cursor
items, next, total, err := h.ipService.ListIPsPaginatedAdvanced(c.Request.Context(), limit, cursor, q, country, addedBy, from, to)
if err != nil {
c.JSON(http.StatusInternalServerError, gin.H{"error": "pagination error"})
return
}
c.JSON(http.StatusOK, gin.H{"items": items, "next": next, "total": total})
}

// Stats returns hour/day/total and top countries.
func (h *APIHandler) Ready(c *gin.Context) {
    dep := map[string]interface{}{"redis": true, "geoip": "unknown"}
    if _, err := h.redisRepo.HGetAllRaw("ips"); err != nil {
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
	hour, day, total, top, err := h.ipService.Stats(c.Request.Context())
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
	c.JSON(http.StatusOK, gin.H{
		"hour": hour,
		"day": day,
		"total": total,
		"top_countries": tops,
	})
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