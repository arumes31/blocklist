package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"blocklist/internal/models"

	"github.com/gin-gonic/gin"
	zlog "github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
)

// Dashboard renders the main dashboard page.
func (h *APIHandler) Dashboard(c *gin.Context) {
	username, _ := c.Get("username")

	ips := h.getCombinedIPs()

	// Preload stats for initial render
	hour, day, totalEver, activeBlocks, top, topASN, topReason, wh, lb, bm, whc, _ := h.ipService.Stats(c.Request.Context())

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

	trend, _ := h.pgRepo.GetBlockTrend()

	h.renderHTML(c, http.StatusOK, "dashboard.html", gin.H{
		"ips":            ips,
		"total_ips":      activeBlocks, // Use value from Stats() for consistency
		"admin_username": h.cfg.GUIAdmin,
		"username":       username,
		"permissions":    permissions,
		"views":          views,
		"block_trend":    trend,
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
			"whitelisted":   whc,
		},
	})
}

func (h *APIHandler) ThreadMap(c *gin.Context) {
	ips := h.getCombinedIPs()
	totalCount := len(ips)
	username, _ := c.Get("username")
	permissions, _ := c.Get("permissions")

	hour, day, _, _, top, _, _, _, _, _, _, _ := h.ipService.Stats(c.Request.Context())

	tops := make([]map[string]interface{}, 0, len(top))
	for _, t := range top {
		tops = append(tops, map[string]interface{}{"Country": t.Country, "Count": t.Count})
	}

	trend, _ := h.pgRepo.GetBlockTrend()

	h.renderHTML(c, http.StatusOK, "thread_map.html", gin.H{
		"total_ips":      totalCount,
		"admin_username": h.cfg.GUIAdmin,
		"username":       username,
		"permissions":    permissions,
		"block_trend":    trend,
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
		zlog.Error().Err(err).Str("username", req.Username).Msg("CreateAdmin failed")
		c.JSON(400, gin.H{"error": "Failed to create admin"})
		return
	}

	actor := c.GetString("username")
	if err := h.pgRepo.LogAction(actor, "CREATE_ADMIN", admin.Username, fmt.Sprintf("Role: %s, Perms: %s", admin.Role, admin.Permissions)); err != nil {
		zlog.Error().Err(err).Str("actor", actor).Str("target", admin.Username).Msg("Failed to record audit log for CREATE_ADMIN")
	}

	c.JSON(200, gin.H{"status": "success", "username": admin.Username})
}

func (h *APIHandler) ChangeAdminPermissions(c *gin.Context) {
	actor := c.GetString("username")

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
	if err := h.pgRepo.LogAction(actor, "CHANGE_PERMISSIONS", req.Username, fmt.Sprintf("From [%s] to [%s]", oldPerms, req.Permissions)); err != nil {
		zlog.Error().Err(err).Str("actor", actor).Str("target", req.Username).Msg("Failed to record audit log for CHANGE_PERMISSIONS")
	}

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
	actor := c.GetString("username")
	if err := h.pgRepo.LogAction(actor, "DELETE_ADMIN", req.Username, "User account and all associated tokens removed"); err != nil {
		zlog.Error().Err(err).Str("actor", actor).Str("target", req.Username).Msg("Failed to record audit log for DELETE_ADMIN")
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

	actor := c.GetString("username")
	if err := h.pgRepo.LogAction(actor, "CHANGE_PASSWORD", req.Username, "Admin password updated"); err != nil {
		zlog.Error().Err(err).Str("actor", actor).Str("target", req.Username).Msg("Failed to record audit log for CHANGE_PASSWORD")
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

	actor := c.GetString("username")
	if err := h.pgRepo.LogAction(actor, "RESET_TOTP", req.Username, "TOTP secret cleared, re-setup required on next login"); err != nil {
		zlog.Error().Err(err).Str("actor", actor).Str("target", req.Username).Msg("Failed to record audit log for RESET_TOTP")
	}

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

func (h *APIHandler) Stats(c *gin.Context) {
	hour, day, totalEver, activeBlocks, top, topASN, topReason, wh, lb, bm, whc, err := h.ipService.Stats(c.Request.Context())
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
		"whitelisted":   whc,
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

func (h *APIHandler) AuditLogExplorer(c *gin.Context) {
	username, _ := c.Get("username")
	actor := c.Query("actor")
	action := c.Query("action")
	query := c.Query("query")
	pageStr := c.DefaultQuery("page", "1")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}
	limit := 50
	offset := (page - 1) * limit

	logs, total, err := h.pgRepo.GetAuditLogsPaginated(limit, offset, actor, action, query)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to fetch audit logs")
		return
	}

	totalPages := (total + limit - 1) / limit
	permissions, _ := c.Get("permissions")

	h.renderHTML(c, http.StatusOK, "audit_logs.html", gin.H{
		"logs":           logs,
		"total":          total,
		"page":           page,
		"total_pages":    totalPages,
		"username":       username,
		"admin_username": h.cfg.GUIAdmin,
		"permissions":    permissions,
		"filters": gin.H{
			"actor":  actor,
			"action": action,
			"query":  query,
		},
	})
}
