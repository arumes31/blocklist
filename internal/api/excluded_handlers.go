package api

import (
	"context"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"blocklist/internal/models"
	"blocklist/internal/security"

	"github.com/gin-gonic/gin"
	zlog "github.com/rs/zerolog/log"
)

// fqdnPattern is a conservative hostname/FQDN matcher (labels of letters,
// digits and hyphens separated by dots; at least one dot). Supports optional
// leading wildcard "*.".
var fqdnPattern = regexp.MustCompile(`^(?i)(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)

// isValidExclusionValue reports whether input is a usable IP, CIDR, or FQDN (including wildcards).
func isValidExclusionValue(input string) bool {
	input = strings.TrimSpace(input)
	if input == "" {
		return false
	}
	if _, err := netip.ParseAddr(input); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(input); err == nil {
		return true
	}
	host := strings.TrimSuffix(input, ".")
	if len(host) > 253 {
		return false
	}
	return fqdnPattern.MatchString(host)
}

// Excluded renders the excluded-list management page.
func (h *APIHandler) Excluded(c *gin.Context) {
	username, _ := c.Get("username")
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	items, err := h.redisRepo.GetExcludedEntries()
	if err != nil {
		h.renderHTML(c, http.StatusInternalServerError, "error.html", gin.H{"error": "Failed to fetch excluded list"})
		return
	}

	externalSources, err := h.pgRepo.GetAllExternalSources()
	if err != nil {
		zlog.Error().Err(err).Msg("Failed to fetch external sources")
	}

	permissions, _ := c.Get("permissions")
	if permissions == nil {
		permissions = ""
	}

	type displayEntry struct {
		models.ExcludedEntry
		ExpiresIn string `json:"expires_in"`
	}

	displayItems := make(map[string]displayEntry)
	for value, entry := range items {
		d := displayEntry{ExcludedEntry: entry}
		if entry.ExpiresAt != "" {
			exp, perr := time.Parse(time.RFC3339, entry.ExpiresAt)
			if perr != nil {
				exp, perr = time.Parse("2006-01-02 15:04:05 UTC", entry.ExpiresAt)
			}
			switch {
			case perr != nil:
				d.ExpiresIn = "ERR"
			case time.Now().After(exp):
				d.ExpiresIn = "EXPIRED"
			default:
				d.ExpiresIn = time.Until(exp).Round(time.Minute).String()
			}
		} else {
			d.ExpiresIn = "NEVER"
		}
		displayItems[value] = d
	}

	// Blocked subnets from configuration are implicitly protected as well.
	var blockedSubnets []string
	if h.cfg != nil && h.cfg.BlockedRanges != "" {
		for _, r := range strings.Split(h.cfg.BlockedRanges, ",") {
			if r = strings.TrimSpace(r); r != "" {
				blockedSubnets = append(blockedSubnets, r)
			}
		}
	}

	h.renderHTML(c, http.StatusOK, "excluded.html", gin.H{
		"excluded_items":   displayItems,
		"blocked_subnets":  blockedSubnets,
		"external_sources": externalSources,
		"username":         username,
		"page":             "excluded",
		"permissions":      permissions,
		"admin_username":   h.cfg.GUIAdmin,
	})
}

// AddExcluded adds an IP, CIDR, or FQDN to the excluded list.
func (h *APIHandler) AddExcluded(c *gin.Context) {
	usernameVal, _ := c.Get("username")
	username, ok := usernameVal.(string)
	if !ok || username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var req struct {
		Value        string `json:"value"`
		IP           string `json:"ip"` // accepted as an alias for value
		Reason       string `json:"reason"`
		Note         string `json:"note"`
		ExpiresAt    string `json:"expires_at"`
		Confirm      bool   `json:"confirm"` // If true, ignore conflict warnings
		AlertEnabled bool   `json:"alert_enabled"`
	}

	if c.ContentType() == "application/json" {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
			return
		}
	} else {
		req.Value = c.PostForm("value")
		req.IP = c.PostForm("ip")
		req.Reason = c.PostForm("reason")
		req.Note = c.PostForm("note")
		req.ExpiresAt = c.PostForm("expires_at")
		req.Confirm, _ = strconv.ParseBool(c.PostForm("confirm"))
		req.AlertEnabled, _ = strconv.ParseBool(c.PostForm("alert_enabled"))
	}

	if len(req.Value) > 255 || len(req.IP) > 255 || len(req.Reason) > 2048 || len(req.Note) > 2048 || len(req.ExpiresAt) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input length limit exceeded"})
		return
	}

	value := strings.TrimSpace(req.Value)
	if value == "" {
		value = strings.TrimSpace(req.IP)
	}
	reason := req.Reason
	if reason == "" {
		reason = req.Note
	}

	if value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Value required (IP, subnet, or FQDN)"})
		return
	}
	if !isValidExclusionValue(value) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid value: expected an IP, CIDR subnet, or FQDN (wildcards like *.example.com supported)"})
		return
	}
	if strings.TrimSpace(reason) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Reason required"})
		return
	}

	if req.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, req.ExpiresAt); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid expires_at format (expected RFC3339)"})
			return
		}
	}

	// Conflict detection
	if !req.Confirm {
		warns := h.ipService.ExclusionConflicts(c.Request.Context(), value)
		if len(warns) > 0 {
			c.JSON(http.StatusConflict, gin.H{
				"status":   "conflict",
				"warnings": warns,
			})
			return
		}
	}

	if err := h.ipService.AddExcluded(c.Request.Context(), value, reason, username, req.ExpiresAt, req.AlertEnabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add to excluded list"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// RemoveExcluded removes a value from the excluded list.
func (h *APIHandler) RemoveExcluded(c *gin.Context) {
	usernameVal, _ := c.Get("username")
	username, ok := usernameVal.(string)
	if !ok || username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	var req struct {
		Value string `json:"value"`
		IP    string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&req); err == nil {
		value := req.Value
		if value == "" {
			value = req.IP
		}
		if value != "" {
			if err := h.ipService.RemoveExcluded(c.Request.Context(), value, username); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove from excluded list"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "success"})
			return
		}
	}

	value := c.Param("value")
	if value == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Value required"})
		return
	}
	if err := h.ipService.RemoveExcluded(c.Request.Context(), value, username); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove from excluded list"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// JSONExcluded returns the excluded list as JSON for API consumers.
func (h *APIHandler) JSONExcluded(c *gin.Context) {
	items, err := h.redisRepo.GetExcludedEntries()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch excluded list"})
		return
	}

	type item struct {
		Value     string               `json:"value"`
		Data      models.ExcludedEntry `json:"data"`
		ExpiresIn string               `json:"expires_in"`
	}

	results := make([]item, 0, len(items))
	for k, v := range items {
		expIn := "NEVER"
		if v.ExpiresAt != "" {
			exp, perr := time.Parse(time.RFC3339, v.ExpiresAt)
			if perr != nil {
				exp, perr = time.Parse("2006-01-02 15:04:05 UTC", v.ExpiresAt)
			}
			switch {
			case perr != nil:
				expIn = "ERR"
			case time.Now().After(exp):
				expIn = "EXPIRED"
			default:
				expIn = time.Until(exp).Round(time.Minute).String()
			}
		}
		results = append(results, item{Value: k, Data: v, ExpiresIn: expIn})
	}

	c.JSON(http.StatusOK, results)
}

func (h *APIHandler) AddExternalSource(c *gin.Context) {
	username, _ := c.Get("username")

	var req struct {
		Name       string `json:"name"`
		URL        string `json:"url"`
		SourceType string `json:"source_type"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	// Security: Input length validation to prevent unconstrained resource consumption
	if len(req.URL) > 2048 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL exceeds maximum length of 2048 characters"})
		return
	}
	if len(req.Name) > 255 || len(req.SourceType) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input fields exceed maximum length of 255 characters"})
		return
	}

	if err := security.IsSafeURL(req.URL); err != nil {
		zlog.Warn().Err(err).Str("url", req.URL).Msg("Attempted to add unsafe external source URL")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or unsafe URL"})
		return
	}

	src := models.ExternalSource{
		Name:                 req.Name,
		URL:                  req.URL,
		SourceType:           req.SourceType,
		RefreshIntervalHours: 6,
	}

	if err := h.pgRepo.CreateExternalSource(src); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create external source"})
		return
	}

	_ = h.pgRepo.LogAction(username.(string), "ADD_EXTERNAL_SOURCE", req.Name, req.URL)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) DeleteExternalSource(c *gin.Context) {
	username, _ := c.Get("username")
	id, _ := strconv.Atoi(c.Param("id"))

	if err := h.pgRepo.DeleteExternalSource(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete external source"})
		return
	}

	_ = h.pgRepo.LogAction(username.(string), "DELETE_EXTERNAL_SOURCE", strconv.Itoa(id), "")
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) RefreshExternalSource(c *gin.Context) {
	// Trigger manual refresh of all sources. The refresh runs in the background
	// (so it outlives this request) but is bounded by a timeout so it cannot run
	// unbounded if a source hangs.
	if h.externalSourceService != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := h.externalSourceService.RefreshAll(ctx); err != nil {
				zlog.Error().Err(err).Msg("Background external source refresh failed")
			}
		}()
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Refresh started in background"})
}
