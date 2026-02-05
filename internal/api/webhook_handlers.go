package api

import (
	"fmt"
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

	// Determine required permission based on action
	requiredPerm := ""
	if data.Act == "ban" || data.Act == "ban-ip" {
		requiredPerm = "block_ips"
	} else if data.Act == "unban" || data.Act == "delete-ban" || data.Act == "unban-ip" {
		requiredPerm = "unblock_ips"
	} else if data.Act == "whitelist" || data.Act == "selfwhitelist" {
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
		if h.hub != nil {
			h.hub.BroadcastEvent("block", map[string]interface{}{
				"ip":         data.IP,
				"data":       entry,
				"source_geo": sourceGeo,
			})
		}
		c.JSON(200, gin.H{"status": "IP banned", "ip": data.IP})
	} else if data.Act == "unban" || data.Act == "delete-ban" || data.Act == "unban-ip" {
		_ = h.pgRepo.LogAction(addedBy, "UNBLOCK", data.IP, "webhook unban")
		if h.hub != nil {
			h.hub.BroadcastEvent("unblock", map[string]interface{}{"ip": data.IP})
		}
		c.JSON(200, gin.H{"status": "IP unbanned", "ip": data.IP})
	} else if data.Act == "whitelist" || data.Act == "selfwhitelist" {
		targetIP := data.IP
		if data.Act == "selfwhitelist" {
			targetIP = c.ClientIP()
		} else if targetIP == "" {
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

		if h.hub != nil {
			h.hub.BroadcastEvent("whitelist", map[string]interface{}{
				"ip":         targetIP,
				"data":       entry,
				"source_geo": sourceGeo,
			})
		}

		c.JSON(http.StatusOK, gin.H{"status": "IP whitelisted", "ip": targetIP})
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
