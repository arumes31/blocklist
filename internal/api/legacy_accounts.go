package api

import (
	"database/sql"
	"net/http"
	"strings"

	"blocklist/internal/models"

	"github.com/gin-gonic/gin"
)

func (h *APIHandler) legacyPermissions(c *gin.Context, value string) (string, bool) {
	permissions, err := models.NormalizePermissions(value)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "The account contains an unknown permission."})
		return "", false
	}
	// Authorize implied workspace rights too: detaching a managed read-only
	// account must not quietly grant saved-view editing via legacy view_ips.
	proposed := models.AdminAccount{AuthSource: "local", Permissions: permissions}
	effective := models.WorkspacePermissions(proposed)
	if _, err := h.validatePermissionSubset(effective, c.GetString("permissions")); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "You cannot grant permissions you do not hold."})
		return "", false
	}
	return permissions, true
}

func (h *APIHandler) createLegacyAdmin(c *gin.Context, account models.AdminAccount, password string) {
	account.Username = strings.TrimSpace(account.Username)
	validName := account.Username != "" && len(account.Username) <= 255
	reservedName := account.Username == h.cfg.GUIAdmin || strings.HasPrefix(account.Username, "entra:")
	if !validName || reservedName || len(account.Role) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Enter a valid account name and role label."})
		return
	}
	// Preserve the original API's shorter passwords. The managed UI retains its
	// 12-byte minimum; bcrypt rejects passwords longer than 72 bytes in both paths.
	if password == "" || len(password) > 72 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Use a non-empty password of at most 72 bytes."})
		return
	}
	if account.Role == "" {
		account.Role = "operator"
	}
	if account.Permissions == "" {
		account.Permissions = "gui_read"
	}
	permissions, allowed := h.legacyPermissions(c, account.Permissions)
	if !allowed {
		return
	}
	account.Permissions, account.AuthSource = permissions, "local"
	hash, err := h.authService.HashPassword(password)
	if err != nil {
		h.identityFailure(c, err)
		return
	}
	account.PasswordHash = hash
	if err := h.identityRepo.CreateLegacyAdmin(c.Request.Context(), account, c.GetString("username")); err != nil {
		h.identityFailure(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "username": account.Username})
}

func (h *APIHandler) changeLegacyAdminPermissions(c *gin.Context, username, value string) {
	account, err := h.pgRepo.GetAdmin(username)
	if err != nil {
		h.identityFailure(c, err)
		return
	}
	if account == nil {
		h.identityFailure(c, sql.ErrNoRows)
		return
	}
	if account.AuthSource == "entra" {
		c.JSON(http.StatusConflict, gin.H{"error": "Assign a managed role to Microsoft accounts."})
		return
	}
	effective := models.WorkspacePermissions(*account)
	if _, err := h.validatePermissionSubset(effective, c.GetString("permissions")); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "You cannot manage an account with permissions you do not hold."})
		return
	}
	permissions, allowed := h.legacyPermissions(c, value)
	if !allowed {
		return
	}
	if err := h.identityRepo.UpdateLegacyAdminPermissions(
		c.Request.Context(),
		*account,
		permissions,
		c.GetString("username"),
	); err != nil {
		h.identityFailure(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}
