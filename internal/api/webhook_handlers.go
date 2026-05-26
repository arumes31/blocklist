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

func (h *APIHandler) getWebhookClientIP(c *gin.Context) string {
	clientIP := c.ClientIP()

	if cfIP := c.GetHeader("CF-Connecting-IP"); cfIP != "" {
		remoteIP, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
		if remoteIP != clientIP {
			if net.ParseIP(cfIP) != nil {
				return cfIP
			}
		}
	}
	return clientIP
}

func (h *APIHandler) validateWebhookIP(ip string) bool {
	return ip != "" && net.ParseIP(ip) != nil
}

func (h *APIHandler) checkWebhookPermissions(c *gin.Context, username, requiredPerm string) bool {
	if username == h.cfg.GUIAdmin {
		return true
	}

	perms, exists := c.Get("permissions")
	if !exists {
		return false
	}

	permStr := perms.(string)
	for _, p := range strings.Split(permStr, ",") {
		if strings.TrimSpace(p) == requiredPerm {
			return true
		}
	}

	zlog.Warn().Str("username", username).Str("permissions", permStr).Str("required", requiredPerm).Msg("Webhook access denied: insufficient permissions")
	return false
}

func (h *APIHandler) getRequiredPermission(act string) string {
	switch act {
	case "ban", "ban-ip":
		return "block_ips"
	case "unban", "delete-ban", "unban-ip":
		return "unblock_ips"
	case "whitelist", "selfwhitelist":
		return "whitelist_ips"
	default:
		return ""
	}
}

func (h *APIHandler) handleWebhookBan(c *gin.Context, data webhookRequest, username, sourceIP, timestamp string, now time.Time, sourceGeo *models.GeoData) {
	if !h.ipService.IsValidIP(data.IP) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "IP cannot be banned (protected or already whitelisted)"})
		return
	}

	addedBy := fmt.Sprintf("Webhook (%s:%s)", username, sourceIP)
	expiresAt := ""
	if !data.Persist {
		tVal := 86400 // Default 24h
		if data.TTL > 0 {
			tVal = data.TTL
		}
		expiresAt = now.Add(time.Duration(tVal) * time.Second).Format("2006-01-02 15:04:05 UTC")
	}

	geo := sourceGeo
	if data.IP != sourceIP {
		geo = h.ipService.GetGeoIP(data.IP)
	}

	entry := models.IPEntry{
		Timestamp:   timestamp,
		Geolocation: geo,
		Reason:      data.Reason,
		AddedBy:     addedBy,
		TTL:         data.TTL,
		ExpiresAt:   expiresAt,
		ThreatScore: h.ipService.CalculateThreatScore(data.IP, data.Reason),
	}

	if h.pgRepo != nil {
		actName := "BLOCK_EPHEMERAL"
		if data.Persist {
			actName = "BLOCK_PERSISTENT"
			_ = h.pgRepo.CreatePersistentBlock(data.IP, entry)
		}
		_ = h.pgRepo.LogAction(addedBy, actName, data.IP, data.Reason)
	}

	_ = h.redisRepo.ExecBlockAtomic(data.IP, entry, now)
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

func (h *APIHandler) handleWebhookUnban(c *gin.Context, data webhookRequest, username, sourceIP string) {
	addedBy := fmt.Sprintf("Webhook (%s:%s)", username, sourceIP)
	_ = h.ipService.UnblockIP(c.Request.Context(), data.IP, username)
	_ = h.pgRepo.LogAction(addedBy, "UNBLOCK", data.IP, "webhook unban")

	if h.hub != nil {
		h.hub.BroadcastEvent("unblock", map[string]interface{}{"ip": data.IP})
	}
	c.JSON(http.StatusOK, gin.H{"status": "IP unbanned", "ip": data.IP})
}

func (h *APIHandler) handleWebhookWhitelist(c *gin.Context, data webhookRequest, username, sourceIP, timestamp string, now time.Time, sourceGeo *models.GeoData) {
	geo := sourceGeo
	if data.IP != sourceIP {
		geo = h.ipService.GetGeoIP(data.IP)
	}

	entry := models.WhitelistEntry{
		Timestamp:   timestamp,
		Geolocation: geo,
		AddedBy:     fmt.Sprintf("WebhookWhitelist (%s:%s)", username, sourceIP),
		Reason:      data.Reason,
	}
	if entry.Reason == "" {
		entry.Reason = "Webhook Whitelist"
	}

	if data.Act == "selfwhitelist" {
		entry.ExpiresAt = now.Add(24 * time.Hour).Format(time.RFC3339)
	}

	_ = h.redisRepo.WhitelistIP(data.IP, entry)
	if h.pgRepo != nil {
		addedBy := fmt.Sprintf("Webhook (%s:%s)", username, sourceIP)
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
		c.JSON(400, gin.H{"status": "invalid request"})
		return
	}

	clientIP := h.getWebhookClientIP(c)
	if net.ParseIP(clientIP) == nil {
		zlog.Error().Str("ip", clientIP).Msg("Webhook: detected invalid client IP")
		c.JSON(http.StatusBadRequest, gin.H{"status": "invalid client IP"})
		return
	}

	if data.Act == "selfwhitelist" {
		data.IP = clientIP
	}

	if !h.validateWebhookIP(data.IP) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "invalid target IP"})
		return
	}

	requiredPerm := h.getRequiredPermission(data.Act)
	if requiredPerm == "" {
		c.JSON(http.StatusNotImplemented, gin.H{"status": "action not implemented"})
		return
	}

	if !h.checkWebhookPermissions(c, username, requiredPerm) {
		c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("Webhook access denied (requires %s)", requiredPerm)})
		return
	}

	metrics.MetricWebhooksTotal.Inc()
	_ = h.redisRepo.IndexWebhookHit(time.Now().UTC())

	now := time.Now().UTC()
	timestamp := now.Format("2006-01-02 15:04:05 UTC")
	sourceGeo := h.ipService.GetGeoIP(clientIP)

	switch data.Act {
	case "ban", "ban-ip":
		h.handleWebhookBan(c, data, username, clientIP, timestamp, now, sourceGeo)
	case "unban", "delete-ban", "unban-ip":
		h.handleWebhookUnban(c, data, username, clientIP)
	case "whitelist", "selfwhitelist":
		h.handleWebhookWhitelist(c, data, username, clientIP, timestamp, now, sourceGeo)
	}
}

func (h *APIHandler) AddOutboundWebhook(c *gin.Context) {
	var wh models.OutboundWebhook
	wh.URL = c.PostForm("url")
	wh.Secret = c.PostForm("secret")
	wh.Events = c.PostForm("events")
	wh.GeoFilter = c.PostForm("geo_filter")
	wh.Active = true

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
