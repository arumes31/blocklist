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

	"github.com/gin-gonic/gin"
	zlog "github.com/rs/zerolog/log"
)

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

	// Extract real client IP
	// Gin's c.ClientIP() already respects TrustedProxies for X-Forwarded-For and X-Real-IP.
	clientIP := c.ClientIP()

	// Only trust CF-Connecting-IP if the request is confirmed to be from a trusted proxy
	if cfIP := c.GetHeader("CF-Connecting-IP"); cfIP != "" {
		remoteIP, _, _ := net.SplitHostPort(c.Request.RemoteAddr)
		if remoteIP != clientIP {
			// Gin has verified the proxy, so we can trust the CF header
			if net.ParseIP(cfIP) != nil {
				clientIP = cfIP
			}
		}
	}

	// Double check syntactic validity of clientIP
	if net.ParseIP(clientIP) == nil {
		zlog.Error().Str("ip", clientIP).Msg("Webhook: detected invalid client IP")
		c.JSON(http.StatusBadRequest, gin.H{"status": "invalid client IP"})
		return
	}

	// Handle selfwhitelist: implicit IP from connection
	if data.Act == "selfwhitelist" {
		data.IP = clientIP
	}

	// Syntactic validation of target IP
	if data.IP == "" || net.ParseIP(data.IP) == nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "invalid target IP"})
		return
	}

	// Determine required permission based on action
	requiredPerm := ""
	switch data.Act {
	case "ban", "ban-ip":
		requiredPerm = "block_ips"
	case "unban", "delete-ban", "unban-ip":
		requiredPerm = "unblock_ips"
	case "whitelist", "selfwhitelist":
		requiredPerm = "whitelist_ips"
	default:
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

	metrics.MetricWebhooksTotal.Inc()
	_ = h.redisRepo.IndexWebhookHit(time.Now().UTC())

	timestamp := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	now := time.Now().UTC()
	sourceIP := clientIP
	addedBy := fmt.Sprintf("Webhook (%s:%s)", username.(string), sourceIP)

	// Efficient GeoIP lookup: cache results if IPs match
	geoMap := make(map[string]*models.GeoData)
	lookup := func(ip string) *models.GeoData {
		if g, ok := geoMap[ip]; ok {
			return g
		}
		g := h.ipService.GetGeoIP(ip)
		geoMap[ip] = g
		return g
	}

	geo := lookup(data.IP)
	sourceGeo := lookup(sourceIP)

	switch data.Act {
	case "ban", "ban-ip":
		// Only check IsValidIP for ban actions
		if !h.ipService.IsValidIP(data.IP) {
			c.JSON(http.StatusBadRequest, gin.H{"status": "IP cannot be banned (protected or already whitelisted)"})
			return
		}

		expiresAt := ""
		if !data.Persist {
			tVal := 86400 // Default 24h
			if data.TTL > 0 {
				tVal = data.TTL
			}
			expiresAt = now.Add(time.Duration(tVal) * time.Second).Format("2006-01-02 15:04:05 UTC")
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

		// Atomic operation updates hash, ZSET index, and persistent counters
		_ = h.redisRepo.ExecBlockAtomic(data.IP, entry, now)

		metrics.MetricBlocksTotal.WithLabelValues("webhook").Inc()
		if h.hub != nil {
			h.hub.BroadcastEvent("block", map[string]interface{}{
				"ip":         data.IP,
				"data":       entry,
				"source_geo": sourceGeo,
			})
		}
		c.JSON(200, gin.H{"status": "IP banned", "ip": data.IP})

	case "unban", "delete-ban", "unban-ip":
		_ = h.ipService.UnblockIP(c.Request.Context(), data.IP, username.(string))
		_ = h.pgRepo.LogAction(addedBy, "UNBLOCK", data.IP, "webhook unban")
		if h.hub != nil {
			h.hub.BroadcastEvent("unblock", map[string]interface{}{"ip": data.IP})
		}
		c.JSON(200, gin.H{"status": "IP unbanned", "ip": data.IP})

	case "whitelist", "selfwhitelist":
		// Target IP already validated syntactically above
		entry := models.WhitelistEntry{
			Timestamp:   timestamp,
			Geolocation: geo,
			AddedBy:     fmt.Sprintf("WebhookWhitelist (%s:%s)", username.(string), sourceIP),
			Reason:      data.Reason,
		}
		if entry.Reason == "" {
			entry.Reason = "Webhook Whitelist"
		}

		// Self-whitelist entries expire after 24h
		if data.Act == "selfwhitelist" {
			entry.ExpiresAt = now.Add(24 * time.Hour).Format(time.RFC3339)
		}

		_ = h.redisRepo.WhitelistIP(data.IP, entry)
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
