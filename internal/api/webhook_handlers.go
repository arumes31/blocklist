package api

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"blocklist/internal/metrics"
	"blocklist/internal/models"
	"blocklist/internal/security"

	"github.com/gin-gonic/gin"
	zlog "github.com/rs/zerolog/log"
)

type webhookRequest struct {
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Act     string `json:"act"`
	TTL     int    `json:"ttl"`
	Persist bool   `json:"persist"`
}

func (h *APIHandler) Webhook(c *gin.Context) {
	// Webhook requires authentication (Bearer token via AuthMiddleware)
	usernameVal, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
		return
	}
	username := usernameVal.(string)

	var data webhookRequest
	if err := c.ShouldBindJSON(&data); err != nil {
		zlog.Error().Err(err).Msg("Webhook: failed to bind JSON")
		c.JSON(http.StatusBadRequest, gin.H{"status": "invalid request"})
		return
	}

	// Extract real client IP
	clientIP := c.ClientIP()
	if net.ParseIP(clientIP) == nil {
		zlog.Error().Str("ip", clientIP).Msg("Webhook: detected invalid client IP")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP address"})
		return
	}

	// Handle selfwhitelist: implicit IP from connection
	if data.Act == "selfwhitelist" {
		data.IP = clientIP
	}

	// Syntactic validation of target IP
	if !h.validateIP(c, data.IP) {
		return
	}

	// Determine required permission and check access
	requiredPerm, err := h.getRequiredPermissionForAction(data.Act)
	if err != nil {
		c.JSON(http.StatusNotImplemented, gin.H{"status": err.Error()})
		return
	}

	if !h.checkWebhookPermissions(c, username, requiredPerm) {
		return
	}

	metrics.MetricWebhooksTotal.Inc()
	_ = h.redisRepo.IndexWebhookHit(time.Now().UTC())

	sourceGeo := h.ipService.GetGeoIP(clientIP)

	switch data.Act {
	case "ban", "ban-ip":
		h.handleWebhookBan(c, data, username, clientIP, sourceGeo)
	case "unban", "delete-ban", "unban-ip":
		h.handleWebhookUnban(c, data, username, clientIP)
	case "whitelist", "selfwhitelist":
		h.handleWebhookWhitelist(c, data, username, clientIP, sourceGeo)
	}
}

func (h *APIHandler) getRequiredPermissionForAction(act string) (string, error) {
	switch act {
	case "ban", "ban-ip":
		return "block_ips", nil
	case "unban", "delete-ban", "unban-ip":
		return "unblock_ips", nil
	case "whitelist", "selfwhitelist":
		return "whitelist_ips", nil
	default:
		return "", fmt.Errorf("action not implemented")
	}
}

func (h *APIHandler) checkWebhookPermissions(c *gin.Context, username string, requiredPerm string) bool {
	if username == h.cfg.GUIAdmin {
		return true
	}

	perms, _ := c.Get("permissions")
	permStr, ok := perms.(string)
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid permissions format"})
		return false
	}

	for _, p := range strings.Split(permStr, ",") {
		if strings.TrimSpace(p) == requiredPerm {
			return true
		}
	}

	zlog.Warn().Str("username", username).Str("permissions", permStr).Str("required", requiredPerm).Msg("Webhook access denied: insufficient permissions")
	c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("Webhook access denied (requires %s)", requiredPerm)})
	return false
}

func (h *APIHandler) handleWebhookBan(c *gin.Context, data webhookRequest, username string, clientIP string, sourceGeo *models.GeoData) {
	duration := 24 * time.Hour
	if data.TTL > 0 {
		duration = time.Duration(data.TTL) * time.Second
	}

	entry, err := h.ipService.BlockIP(c.Request.Context(), data.IP, data.Reason, username, clientIP, data.Persist, duration)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": fmt.Sprintf("Block failed: %v", err)})
		return
	}

	metrics.MetricBlocksTotal.WithLabelValues("webhook").Inc()
	if h.hub != nil {
		h.hub.BroadcastEvent("block", map[string]interface{}{
			"ip":         data.IP,
			"data":       entry,
			"source_geo": sourceGeo,
		})
	}
	c.JSON(http.StatusOK, gin.H{"status": "IP banned", "ip": data.IP})
}

func (h *APIHandler) handleWebhookUnban(c *gin.Context, data webhookRequest, username string, clientIP string) {
	addedBy := fmt.Sprintf("Webhook (%s:%s)", username, clientIP)

	if err := h.ipService.UnblockIP(c.Request.Context(), data.IP, username); err != nil {
		zlog.Error().Err(err).Str("ip", data.IP).Str("by", addedBy).Msg("Webhook unban failed")
		c.JSON(http.StatusInternalServerError, gin.H{"status": fmt.Sprintf("Unblock failed: %v", err)})
		return
	}

	if h.pgRepo != nil {
		_ = h.pgRepo.LogAction(addedBy, "UNBLOCK", data.IP, "webhook unban")
	}

	if h.hub != nil {
		h.hub.BroadcastEvent("unblock", map[string]interface{}{"ip": data.IP})
	}
	c.JSON(http.StatusOK, gin.H{"status": "IP unbanned", "ip": data.IP})
}

func (h *APIHandler) handleWebhookWhitelist(c *gin.Context, data webhookRequest, username string, clientIP string, sourceGeo *models.GeoData) {
	now := time.Now().UTC()
	timestamp := now.Format("2006-01-02 15:04:05 UTC")
	addedBy := fmt.Sprintf("Webhook (%s:%s)", username, clientIP)
	geo := h.ipService.GetGeoIP(data.IP)

	entry := models.WhitelistEntry{
		Timestamp:   timestamp,
		Geolocation: geo,
		AddedBy:     fmt.Sprintf("WebhookWhitelist (%s:%s)", username, clientIP),
		Reason:      data.Reason,
	}
	if entry.Reason == "" {
		entry.Reason = "Webhook Whitelist"
	}

	if data.Act == "selfwhitelist" {
		entry.ExpiresAt = now.Add(24 * time.Hour).Format(time.RFC3339)
	}

	if err := h.redisRepo.WhitelistIP(data.IP, entry); err != nil {
		zlog.Error().Err(err).Str("ip", data.IP).Str("by", addedBy).Msg("Webhook whitelist failed")
		c.JSON(http.StatusInternalServerError, gin.H{"status": fmt.Sprintf("Whitelist failed: %v", err)})
		return
	}

	if h.pgRepo != nil {
		_ = h.pgRepo.LogAction(addedBy, "WHITELIST", data.IP, entry.Reason)
	}

	if h.hub != nil {
		h.hub.BroadcastEvent("whitelist", map[string]interface{}{
			"ip":         data.IP,
			"data":       entry,
			"source_geo": sourceGeo,
		})
	}

	c.JSON(http.StatusOK, gin.H{"status": "IP whitelisted", "ip": data.IP})
}

func (h *APIHandler) AddOutboundWebhook(c *gin.Context) {
	var wh models.OutboundWebhook
	wh.URL = c.PostForm("url")
	wh.Secret = c.PostForm("secret")
	wh.Events = c.PostForm("events")
	wh.GeoFilter = c.PostForm("geo_filter")
	wh.Active = true

	// Security: Input length validation to prevent unconstrained resource consumption
	if len(wh.URL) > 2048 {
		c.String(http.StatusBadRequest, "URL exceeds maximum length of 2048 characters")
		return
	}
	if len(wh.Secret) > 255 || len(wh.Events) > 255 || len(wh.GeoFilter) > 255 {
		c.String(http.StatusBadRequest, "Input fields exceed maximum length of 255 characters")
		return
	}

	if err := security.IsSafeURL(wh.URL); err != nil {
		zlog.Warn().Err(err).Str("url", wh.URL).Msg("Attempted to add unsafe webhook URL")
		c.String(http.StatusBadRequest, "Invalid or unsafe webhook URL")
		return
	}

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
