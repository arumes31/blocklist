package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"blocklist/internal/models"

	"github.com/gin-gonic/gin"
	zlog "github.com/rs/zerolog/log"
)

func (h *APIHandler) isIPInCIDRs(ipStr string, cidrs string) bool {
	if cidrs == "" {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	cidrList := strings.Split(cidrs, ",")
	for _, cidr := range cidrList {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			if network.Contains(ip) {
				return true
			}
		} else {
			// Try as plain IP
			if cidr == ipStr {
				return true
			}
		}
	}
	return false
}

func (h *APIHandler) BlockCheckMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// Bypass block check for login page and static assets to avoid lockout
		path := c.Request.URL.Path
		if path == "/login" || strings.HasPrefix(path, "/static") || strings.HasPrefix(path, "/js") || strings.HasPrefix(path, "/cd") {
			c.Next()
			return
		}

		if h.ipService.IsBlocked(clientIP) {
			zlog.Warn().Str("path", path).Msg("Blocked IP attempted access")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Your IP has been blocked due to security policies.",
			})
			return
		}
		c.Next()
	}
}

// BlockIP handles the request to block an IP address.
func (h *APIHandler) BlockIP(c *gin.Context) {
	username, _ := c.Get("username")

	var req struct {
		IP      string `json:"ip"`
		Persist bool   `json:"persist"`
		Reason  string `json:"reason"`
		TTL     int    `json:"ttl"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	ip := req.IP
	if net.ParseIP(ip) == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP address"})
		return
	}

	duration := time.Duration(0)
	if req.TTL > 0 {
		duration = time.Duration(req.TTL) * time.Minute
	}

	// Permission check?
	// Assuming permission middleware already ran.

	err := h.ipService.BlockIP(c.Request.Context(), ip, req.Reason, username.(string), c.ClientIP(), req.Persist, duration)
	if err != nil {
		zlog.Error().Err(err).Msg("Failed to block IP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to block IP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "blocked", "ip": ip})
}

// UnblockIP handles the request to unblock an IP address.
func (h *APIHandler) UnblockIP(c *gin.Context) {
	username, _ := c.Get("username")

	var req struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	ip := req.IP
	if net.ParseIP(ip) == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP address"})
		return
	}

	err := h.ipService.UnblockIP(c.Request.Context(), ip, username.(string))
	if err != nil {
		zlog.Error().Err(err).Msg("Failed to unblock IP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to unblock IP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "unblocked", "ip": ip})
}

func (h *APIHandler) BulkBlock(c *gin.Context) {
	username, _ := c.Get("username")
	var req struct {
		IPs     []string `json:"ips"`
		Reason  string   `json:"reason"`
		Persist bool     `json:"persist"`
		TTL     int      `json:"ttl"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IPs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	ttl := 0
	if req.TTL > 0 {
		ttl = req.TTL * 60
	}

	err := h.ipService.BulkBlock(c.Request.Context(), req.IPs, req.Reason, username.(string), c.ClientIP(), req.Persist, ttl)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Bulk block failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "count": len(req.IPs)})
}

func (h *APIHandler) BulkUnblock(c *gin.Context) {
	username, _ := c.Get("username")
	var req struct {
		IPs []string `json:"ips"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IPs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	err := h.ipService.BulkUnblock(c.Request.Context(), req.IPs, username.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Bulk unblock failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "count": len(req.IPs)})
}

func (h *APIHandler) Whitelist(c *gin.Context) {
	username, _ := c.Get("username")
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	items, err := h.redisRepo.GetWhitelistedIPs()
	if err != nil {
		h.renderHTML(c, http.StatusInternalServerError, "error.html", gin.H{"error": "Failed to fetch whitelist"})
		return
	}

	permissions, _ := c.Get("permissions")
	if permissions == nil {
		permissions = ""
	}

	h.renderHTML(c, http.StatusOK, "whitelist.html", gin.H{
		"whitelisted_ips": items,
		"username":        username,
		"page":            "whitelist",
		"permissions":     permissions,
		"admin_username":  h.cfg.GUIAdmin,
	})
}

func (h *APIHandler) AddWhitelist(c *gin.Context) {
	username, _ := c.Get("username")

	var req struct {
		IP     string `json:"ip"`
		Note   string `json:"note"`
		Reason string `json:"reason"` // Frontend sends 'reason', handler used 'note' previously? Service uses 'note'?
	}

	// Try JSON first
	if err := c.ShouldBindJSON(&req); err != nil {
		// Fallback to Form
		req.IP = c.PostForm("ip")
		req.Note = c.PostForm("note")
		if req.Note == "" {
			req.Note = c.PostForm("reason")
		}
	}

	// Map reason to note if needed, or vice-versa
	note := req.Note
	if note == "" {
		note = req.Reason
	}

	if req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP required"})
		return
	}

	// Validate IP or CIDR
	if net.ParseIP(req.IP) == nil {
		_, _, err := net.ParseCIDR(req.IP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP or CIDR"})
			return
		}
	}

	if err := h.ipService.WhitelistIP(c.Request.Context(), req.IP, note, username.(string)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to whitelist IP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) RemoveWhitelist(c *gin.Context) {
	username, _ := c.Get("username")

	// Check JSON body first (Frontend uses JSON)
	var req struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&req); err == nil && req.IP != "" {
		if err := h.ipService.RemoveWhitelist(c.Request.Context(), req.IP, username.(string)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove from whitelist"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "success"})
		return
	}

	// Fallback to Param (if called via /remove_whitelist/:ip which currently doesn't exist but for safety)
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP required"})
		return
	}

	if err := h.ipService.RemoveWhitelist(c.Request.Context(), ip, username.(string)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove from whitelist"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) JSONWhitelists(c *gin.Context) {
	items, err := h.redisRepo.GetWhitelistedIPs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch whitelist"})
		return
	}

	type item struct {
		IP   string                `json:"ip"`
		Data models.WhitelistEntry `json:"data"`
	}
	var res []item
	for k, v := range items {
		res = append(res, item{IP: k, Data: v})
	}
	c.JSON(http.StatusOK, res)
}

func (h *APIHandler) RawIPs(c *gin.Context) {
	ips, err := h.redisRepo.GetBlockedIPs()
	if err != nil {
		c.String(http.StatusInternalServerError, "Error fetching IPs")
		return
	}
	// RawIPs prints ips newline separated.
	// GetBlockedIPs return map[string]IPEntry.
	var list []string
	for ip := range ips {
		list = append(list, ip)
	}
	c.String(http.StatusOK, strings.Join(list, "\n"))
}

func (h *APIHandler) JSONIPs(c *gin.Context) {
	ips, err := h.redisRepo.GetBlockedIPs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching IPs"})
		return
	}
	c.JSON(http.StatusOK, ips)
}

func (h *APIHandler) GetIPDetails(c *gin.Context) {
	ip := c.Param("ip")
	details, err := h.ipService.GetIPDetails(c.Request.Context(), ip)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "IP not found"})
		return
	}
	c.JSON(http.StatusOK, details)
}

// IPsPaginated provides server-side pagination and search across all records.
// Query params: limit (int), cursor (opaque string), query (string)
// Response: { items: [{ip, data}], next: "cursor", total: N }
func (h *APIHandler) IPsPaginated(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "50")
	limit, _ := strconv.Atoi(limitStr)
	if limit > 1000 {
		limit = 1000
	}

	q := strings.TrimSpace(c.Query("query"))
	cursor := c.Query("cursor")
	country := strings.TrimSpace(c.Query("country"))
	addedBy := strings.TrimSpace(c.Query("added_by"))
	from := strings.TrimSpace(c.Query("from"))
	to := strings.TrimSpace(c.Query("to"))
	items, next, total, err := h.ipService.ListIPsPaginatedAdvanced(c.Request.Context(), limit, cursor, q, country, addedBy, from, to)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "pagination error"})
		return
	}
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
		ip, _ := item["ip"].(string)
		data, ok := item["data"].(*models.IPEntry)
		if !ok || data == nil {
			// Try as value type if pointer assertion fails
			val, okVal := item["data"].(models.IPEntry)
			if okVal {
				data = &val
			} else {
				continue // Skip invalid entries
			}
		}

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
