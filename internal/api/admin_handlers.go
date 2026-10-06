package api

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"blocklist/internal/models"
	"blocklist/internal/service"

	"github.com/gin-gonic/gin"
	zlog "github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
)

// Dashboard renders the main dashboard page.
func (h *APIHandler) Dashboard(c *gin.Context) {
	username, _ := c.Get("username")

	// Preload stats for initial render
	hour, day, totalEver, activeBlocks, top, topASN, topReason, wh, lb, bm, whc, err := h.ipService.Stats(c.Request.Context())
	if err != nil {
		zlog.Error().Err(err).Msg("failed to fetch dashboard stats")
		c.String(http.StatusInternalServerError, "failed to fetch dashboard stats")
		return
	}

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
			"whitelisted":   whc,
			"excluded":      h.ipService.GetExcludedCount(c.Request.Context()),
		},
	})
}

func (h *APIHandler) ThreatMap(c *gin.Context) {
	username, _ := c.Get("username")
	_, hasPermissions := c.Get("permissions")
	permissions := c.GetString("permissions")
	statsAllowed := hasPermissions && username == h.cfg.GUIAdmin
	for _, permission := range strings.Split(permissions, ",") {
		if strings.TrimSpace(permission) == "view_stats" {
			statsAllowed = true
			break
		}
	}

	// The map requires view_ips; aggregate statistics additionally require view_stats.
	// Null values distinguish restricted statistics from a real count of zero.
	bootstrap := gin.H{
		"total":           nil,
		"hour":            nil,
		"day":             nil,
		"blocks_minute":   nil,
		"whitelisted":     nil,
		"top_countries":   []gin.H{},
		"top_reasons":     []gin.H{},
		"trend":           []gin.H{},
		"trend_available": false,
		"stats_allowed":   statsAllowed,
	}

	if statsAllowed {
		hour, day, _, activeBlocks, top, _, topReasons, _, _, blocksMinute, whitelisted, err := h.ipService.Stats(c.Request.Context())
		if err != nil {
			zlog.Error().Err(err).Msg("failed to fetch threat map stats")
			c.String(http.StatusInternalServerError, "failed to fetch threat map stats")
			return
		}
		bootstrap["total"] = activeBlocks
		bootstrap["hour"] = hour
		bootstrap["day"] = day
		bootstrap["blocks_minute"] = blocksMinute
		bootstrap["whitelisted"] = whitelisted

		countries := make([]gin.H, 0, len(top))
		for _, country := range top {
			countries = append(countries, gin.H{"country": country.Country, "count": country.Count})
		}
		bootstrap["top_countries"] = countries
		reasons := make([]gin.H, 0, len(topReasons))
		for _, reason := range topReasons {
			reasons = append(reasons, gin.H{"reason": reason.Reason, "count": reason.Count})
		}
		bootstrap["top_reasons"] = reasons

		trend, err := h.pgRepo.GetBlockTrend()
		if err != nil {
			zlog.Error().Err(err).Msg("failed to get threat map block trend")
		} else {
			trendData := make([]gin.H, 0, len(trend))
			for _, point := range trend {
				trendData = append(trendData, gin.H{"x": point.Hour, "y": point.Count})
			}
			bootstrap["trend"] = trendData
			bootstrap["trend_available"] = true
		}
	}

	bootstrapJSON, err := json.Marshal(bootstrap)
	if err != nil {
		zlog.Error().Err(err).Msg("failed to marshal threat map data")
		c.String(http.StatusInternalServerError, "failed to render threat map")
		return
	}

	h.renderHTML(c, http.StatusOK, "threat_map.html", gin.H{
		"admin_username": h.cfg.GUIAdmin,
		"username":       username,
		"permissions":    permissions,
		// json.Marshal escapes HTML-sensitive characters before use in a script element.
		"map_bootstrap_json": template.JS(string(bootstrapJSON)), // #nosec G203
		"active_page":        "threat-map",
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
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	status := "UP"
	dbStatus := "OK"
	readDbStatus := "OK"
	redisStatus := "OK"
	if h.redisRepo != nil {
		if err := h.redisRepo.Ping(ctx); err != nil {
			redisStatus = "ERROR"
			status = "DEGRADED"
		}
	} else {
		redisStatus = "MISSING"
		status = "DEGRADED"
	}
	if h.pgRepo != nil {
		primaryErr, readErr := h.pgRepo.Ping(ctx)
		if primaryErr != nil {
			dbStatus = "ERROR"
			status = "DEGRADED"
		}
		// Check read replica if it's different from primary
		if readErr != nil {
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
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16384)
	var req struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		Role          string `json:"role"`
		Permissions   string `json:"permissions"`
		AuthSource    string `json:"auth_source"`
		EntraUPN      string `json:"entra_upn"`
		EntraTenantID string `json:"entra_tenant_id"`
		EntraObjectID string `json:"entra_object_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	if h.identityRepo != nil {
		// The original API had no auth_source and accepted individual permissions.
		// New role-managed UI requests explicitly send local or entra.
		if req.AuthSource == "" {
			identityFields := req.EntraUPN != "" || req.EntraTenantID != "" || req.EntraObjectID != ""
			if identityFields {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Specify auth_source for Microsoft accounts."})
				return
			}
			h.createLegacyAdmin(c, models.AdminAccount{
				Username: req.Username, Role: req.Role, Permissions: req.Permissions,
			}, req.Password)
			return
		}
		if req.Role == "" {
			req.Role = "viewer"
		}
		if req.AuthSource == "" {
			req.AuthSource = "local"
		}
		prebound := req.EntraTenantID != "" || req.EntraObjectID != ""
		if req.AuthSource == "entra" && !prebound {
			upn, err := models.NormalizeEntraUPN(req.EntraUPN)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Enter the exact Microsoft sign-in UPN, such as user@company.com.",
				})
				return
			}
			req.EntraUPN, req.Username = upn, upn
		}
		req.Username = strings.TrimSpace(req.Username)
		validName := req.Username != "" && len(req.Username) <= 255 && !strings.HasPrefix(req.Username, "entra:")
		validSource := req.AuthSource == "local" || req.AuthSource == "entra"
		if !validName || !validSource || req.Username == h.cfg.GUIAdmin {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Enter a valid username and authentication source."})
			return
		}
		role, err := h.identityRepo.GetRole(c.Request.Context(), req.Role)
		if err != nil {
			h.identityFailure(c, err)
			return
		}
		if _, err := h.validatePermissionSubset(role.Permissions, c.GetString("permissions")); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "You cannot assign permissions you do not hold."})
			return
		}
		admin := models.AdminAccount{Username: req.Username, Role: role.ID, AuthSource: req.AuthSource, EntraUPN: strings.TrimSpace(req.EntraUPN)}
		if req.AuthSource == "local" {
			if len(req.Password) < 12 || len(req.Password) > 72 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Use a password between 12 and 72 bytes."})
				return
			}
			admin.PasswordHash, err = h.authService.HashPassword(req.Password)
			if err != nil {
				h.identityFailure(c, err)
				return
			}
			admin.EntraUPN = ""
		} else if prebound {
			if !service.ValidEntraID(req.EntraTenantID) || !service.ValidEntraID(req.EntraObjectID) || len(admin.EntraUPN) > 255 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Enter the account's immutable Microsoft tenant ID and user object ID."})
				return
			}
			if h.cfg.EntraTenantID != "" && !strings.EqualFold(req.EntraTenantID, h.cfg.EntraTenantID) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "The tenant ID must match this workspace's Entra tenant."})
				return
			}
			admin.EntraTenantID, admin.EntraObjectID = &req.EntraTenantID, &req.EntraObjectID
		}
		if err := h.identityRepo.CreateManagedAdmin(c.Request.Context(), admin, c.GetString("username")); err != nil {
			h.identityFailure(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "success", "username": admin.Username})
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
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16384)
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
	if h.identityRepo != nil {
		h.changeLegacyAdminPermissions(c, req.Username, req.Permissions)
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

	logs := []models.AuditLog{}
	roles := []models.AccessRole{}
	if h.identityRepo != nil {
		var err error
		roles, err = h.identityRepo.ListRoles(c.Request.Context())
		if err != nil {
			h.identityFailure(c, err)
			return
		}
	} else {
		logs, _ = h.pgRepo.GetAuditLogs(100)
	}
	userPerms, _ := c.Get("permissions")

	h.renderHTML(c, http.StatusOK, "admin_management.html", gin.H{
		"admins":         adminMap,
		"roles":          roles,
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
	if !h.canManageAccount(c, req.Username) {
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
	if !h.canManageAccount(c, req.Username) {
		return
	}
	if h.identityRepo != nil {
		admin, err := h.pgRepo.GetAdmin(req.Username)
		if err != nil || admin == nil {
			c.Status(http.StatusNotFound)
			return
		}
		if admin.AuthSource == "entra" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Microsoft manages this account's password."})
			return
		}
		if len(req.NewPassword) < 12 || len(req.NewPassword) > 72 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Use a password between 12 and 72 bytes."})
			return
		}
	}

	hash, err := h.authService.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password could not be saved."})
		return
	}
	err = h.pgRepo.UpdateAdminPassword(req.Username, hash)
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

	// The GUIAdmin account is configuration-driven and is the recovery path of
	// last resort. Allowing its TOTP to be cleared here would let any holder of
	// manage_admins strip 2FA from the primary account and then enrol their own
	// device through the self-service setup flow.
	if req.Username == h.cfg.GUIAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "TOTP for GUIAdmin cannot be reset via UI"})
		return
	}
	if !h.canManageAccount(c, req.Username) {
		return
	}

	// Clear TOTP secret to force re-setup on next login.
	if h.identityRepo != nil {
		admin, err := h.pgRepo.GetAdmin(req.Username)
		if err != nil || admin == nil {
			c.Status(http.StatusNotFound)
			return
		}
		if admin.AuthSource == "entra" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Microsoft manages this account's authentication."})
			return
		}
	}
	if err := h.pgRepo.UpdateAdminToken(req.Username, ""); err != nil {
		zlog.Error().Err(err).Str("target", req.Username).Msg("Failed to clear admin TOTP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	actor := c.GetString("username")
	if err := h.pgRepo.LogAction(actor, "RESET_TOTP", req.Username, "TOTP secret cleared, re-setup required on next login"); err != nil {
		zlog.Error().Err(err).Str("actor", actor).Str("target", req.Username).Msg("Failed to record audit log for RESET_TOTP")
	}

	c.JSON(200, gin.H{"status": "success"})
}

func (h *APIHandler) GetQR(c *gin.Context) {
	username := c.Param("username")

	// A TOTP secret is a credential, not account metadata: anyone holding it can
	// generate that account's codes indefinitely. Enrolment is self-service via
	// the login flow, so there is no legitimate reason to hand one account's
	// secret to another user, however privileged.
	if actor := c.GetString("username"); actor == "" || actor != username {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "TOTP secrets can only be retrieved for your own account"})
		return
	}

	admin, err := h.pgRepo.GetAdmin(username)
	if err != nil || admin == nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	// Nothing to render before enrolment; the login flow issues the provisioning
	// secret. Returning a QR for an empty secret would encode a usable "empty key".
	if admin.Token == "" {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "No TOTP secret is enrolled for this account"})
		return
	}

	// Construct the provisioning URL through net/url so account names cannot
	// alter the path or inject query parameters.
	query := url.Values{
		"issuer": {"Blocklist App"},
		"secret": {admin.Token},
	}
	provisioningURL := (&url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "Blocklist App:" + username,
		RawQuery: query.Encode(),
	}).String()

	pngData, err := h.generateQRWithLogo(provisioningURL)
	if err != nil {
		pngData, err = qrcode.Encode(provisioningURL, qrcode.Medium, 256)
		if err != nil {
			zlog.Error().Err(err).Str("username", username).Msg("Failed to generate TOTP QR code")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to generate QR code"})
			return
		}
	}
	c.Data(http.StatusOK, "image/png", pngData)
}

func (h *APIHandler) Stats(c *gin.Context) {
	hour, day, totalEver, activeBlocks, top, topASN, topReason, wh, lb, bm, whc, err := h.ipService.Stats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stats error"})
		return
	}

	// shape to match frontend expectations
	tops := make([]gin.H, 0, len(top))
	for _, t := range top {
		tops = append(tops, gin.H{"country": t.Country, "count": t.Count})
	}

	asns := make([]gin.H, 0, len(topASN))
	for _, a := range topASN {
		asns = append(asns, gin.H{"asn": a.ASN, "asn_org": a.ASNOrg, "count": a.Count})
	}

	reasons := make([]gin.H, 0, len(topReason))
	for _, r := range topReason {
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
		"excluded":      h.ipService.GetExcludedCount(c.Request.Context()),
	})
}

func (h *APIHandler) Settings(c *gin.Context) {
	username, _ := c.Get("username")
	webhooks, _ := h.pgRepo.GetActiveWebhooks()
	tokens, _ := h.pgRepo.GetAPITokens(username.(string))

	userPerms, _ := c.Get("permissions")
	hasGlobalTokensPerm := h.can(c, "manage_global_tokens")
	for _, p := range strings.Split(userPerms.(string), ",") {
		if strings.TrimSpace(p) == "manage_global_tokens" {
			hasGlobalTokensPerm = true
			break
		}
	}

	var allTokens []models.APIToken
	if hasGlobalTokensPerm || h.can(c, "view_api_tokens") {
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
		"show_global_tokens":   hasGlobalTokensPerm || h.can(c, "view_api_tokens"),
		"can_manage_webhooks":  h.can(c, "manage_webhooks"),
		"can_manage_tokens":    h.can(c, "manage_api_tokens"),
		"entra_auto_provision": h.cfg.EntraAutoProvision,
	})
}

func (h *APIHandler) AuditLogExplorer(c *gin.Context) {
	h.logExplorer(c, "system")
}

func (h *APIHandler) EventLogExplorer(c *gin.Context) {
	h.logExplorer(c, "events")
}

func (h *APIHandler) logExplorer(c *gin.Context, category string) {
	username, _ := c.Get("username")
	actor := c.Query("actor")
	action := c.Query("action")
	query := c.Query("query")
	pageStr := c.DefaultQuery("page", "1")
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 || page > 1000000 {
		page = 1
	}
	limit := 50
	offset := (page - 1) * limit

	var logs []models.AuditLog
	var total int
	if h.identityRepo != nil {
		logs, total, err = h.identityRepo.ListLogs(c.Request.Context(), models.LogFilter{
			Category: category, Actor: actor, Action: action, Query: query, Limit: limit, Offset: offset,
		})
	} else {
		logs, total, err = h.pgRepo.GetAuditLogsPaginated(limit, offset, actor, action, query)
	}
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to fetch audit logs")
		return
	}

	totalPages := (total + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}
	title, description, path := "System audit logs", "Sign-ins, account access, roles, and configuration changes.", "/audit-logs"
	actions := []string{"LOGIN_SUCCESS", "LOGIN_FAILURE", "ENTRA_LOGIN_SUCCESS", "ENTRA_LOGIN_FAILURE", "TOTP_SETUP", "CREATE_ADMIN", "DELETE_ADMIN", "CHANGE_PASSWORD", "RESET_TOTP", "CHANGE_PERMISSIONS", "CREATE_ROLE", "UPDATE_ROLE", "DELETE_ROLE", "ASSIGN_ROLE", "CREATE_TOKEN", "DELETE_TOKEN", "UPDATE_TOKEN_PERMS", "ADMIN_REVOKE_TOKEN", "ADD_EXTERNAL_SOURCE", "DELETE_EXTERNAL_SOURCE"}
	if category == "events" {
		title, description, path = "Event logs", "Blocking, unblocking, whitelist, and exclusion activity.", "/event-logs"
		actions = models.EventActions
	}
	permissions, _ := c.Get("permissions")

	h.renderHTML(c, http.StatusOK, "audit_logs.html", gin.H{
		"logs":            logs,
		"log_title":       title,
		"log_description": description,
		"log_path":        path,
		"active_page":     strings.TrimPrefix(path, "/"),
		"log_actions":     actions,
		"total":           total,
		"page":            page,
		"total_pages":     totalPages,
		"username":        username,
		"admin_username":  h.cfg.GUIAdmin,
		"permissions":     permissions,
		"filters": gin.H{
			"actor":  actor,
			"action": action,
			"query":  query,
		},
	})
}
