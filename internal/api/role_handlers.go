package api

import (
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"blocklist/internal/models"
	"blocklist/internal/repository"

	"github.com/gin-gonic/gin"
	zlog "github.com/rs/zerolog/log"
)

var roleKey = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func (h *APIHandler) can(c *gin.Context, permission string) bool {
	if h.cfg != nil && h.cfg.GUIAdmin != "" && c.GetString("username") == h.cfg.GUIAdmin && !c.GetBool("token_auth") {
		return true
	}
	return models.HasPermission(c.GetString("permissions"), permission)
}

func (h *APIHandler) identityFailure(c *gin.Context, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		c.JSON(http.StatusNotFound, gin.H{"error": "Account or role no longer exists. Refresh and try again."})
	case errors.Is(err, repository.ErrIdentityConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "This record changed or its name is already used. Refresh before saving."})
	case errors.Is(err, repository.ErrRoleInUse):
		c.JSON(http.StatusConflict, gin.H{"error": "Assign this role's accounts to another role before deleting it."})
	case errors.Is(err, repository.ErrRoleProtected):
		c.JSON(http.StatusConflict, gin.H{"error": "Built-in roles can be edited, but cannot be deleted."})
	default:
		zlog.Error().Err(err).Msg("Identity operation failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "The change could not be saved. Try again."})
	}
}

func (h *APIHandler) canManageAccount(c *gin.Context, username string) bool {
	if h.identityRepo == nil {
		return true
	}
	admin, err := h.pgRepo.GetAdmin(username)
	if err != nil || admin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found."})
		return false
	}
	if _, err := h.validatePermissionSubset(models.WorkspacePermissions(*admin), c.GetString("permissions")); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "You cannot manage an account with permissions you do not hold."})
		return false
	}
	return true
}

func (h *APIHandler) roleData(c *gin.Context) (gin.H, error) {
	roles, err := h.identityRepo.ListRoles(c.Request.Context())
	if err != nil {
		return nil, err
	}
	return gin.H{
		"roles": roles, "permission_catalog": models.PermissionCatalog,
		"username": c.GetString("username"), "permissions": c.GetString("permissions"),
		"admin_username": h.cfg.GUIAdmin, "active_page": "roles",
	}, nil
}

func (h *APIHandler) RoleManagement(c *gin.Context) {
	data, err := h.roleData(c)
	if err != nil {
		h.identityFailure(c, err)
		return
	}
	h.renderHTML(c, http.StatusOK, "roles.html", data)
}

func (h *APIHandler) ListRoles(c *gin.Context) {
	data, err := h.roleData(c)
	if err != nil {
		h.identityFailure(c, err)
		return
	}
	c.JSON(http.StatusOK, data)
}

func (h *APIHandler) roleForManagement(c *gin.Context, id string) (*models.AccessRole, bool) {
	role, err := h.identityRepo.GetRole(c.Request.Context(), id)
	if err != nil {
		h.identityFailure(c, err)
		return nil, false
	}
	if _, err := h.validatePermissionSubset(role.Permissions, c.GetString("permissions")); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "You cannot manage a role with permissions you do not hold."})
		return nil, false
	}
	return role, true
}

func (h *APIHandler) SaveRole(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16384)
	var role models.AccessRole
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Enter a valid role."})
		return
	}
	role.Name = strings.TrimSpace(role.Name)
	role.Description = strings.TrimSpace(role.Description)
	if c.Request.Method == http.MethodPost {
		role.Revision = 0
	} else {
		role.ID = c.Param("id")
		if role.Revision < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh this role before saving."})
			return
		}
	}
	validText := role.Name != "" && len(role.Name) <= 80 && len(role.Description) <= 500
	if !roleKey.MatchString(role.ID) || !validText {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Use a name up to 80 characters and a lowercase role key without spaces."})
		return
	}
	permissions, err := models.NormalizePermissions(role.Permissions)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "The role contains an unknown permission."})
		return
	}
	if _, err := h.validatePermissionSubset(permissions, c.GetString("permissions")); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "You cannot grant permissions you do not hold."})
		return
	}
	role.Permissions = permissions
	if role.Revision > 0 {
		current, allowed := h.roleForManagement(c, role.ID)
		if !allowed {
			return
		}
		// Bind authorization to this exact snapshot, including against a guessed
		// future revision. The repository's conditional UPDATE closes the race.
		if current.Revision != role.Revision {
			h.identityFailure(c, repository.ErrIdentityConflict)
			return
		}
	}
	if err := h.identityRepo.SaveRole(c.Request.Context(), role, c.GetString("username")); err != nil {
		h.identityFailure(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) DeleteRole(c *gin.Context) {
	role, allowed := h.roleForManagement(c, c.Param("id"))
	if !allowed {
		return
	}
	if err := h.identityRepo.DeleteRole(
		c.Request.Context(),
		role.ID,
		c.GetString("username"),
		role.Revision,
	); err != nil {
		h.identityFailure(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (h *APIHandler) ChangeAdminRole(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Override bool   `json:"entra_role_override"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Username) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Enter a valid account and role."})
		return
	}
	if req.Username == h.cfg.GUIAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "The recovery administrator's access is configuration-managed."})
		return
	}
	if !h.canManageAccount(c, req.Username) {
		return
	}
	role, err := h.identityRepo.GetRole(c.Request.Context(), req.Role)
	if err != nil {
		h.identityFailure(c, err)
		return
	}
	if _, err := h.validatePermissionSubset(role.Permissions, c.GetString("permissions")); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "You cannot assign a role with permissions you do not hold."})
		return
	}
	admin := models.AdminAccount{Username: req.Username, Role: role.ID, EntraRoleOverride: req.Override}
	if err := h.identityRepo.AssignAdminRole(c.Request.Context(), admin, c.GetString("username")); err != nil {
		h.identityFailure(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}
