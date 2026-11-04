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
	if h.isRecoverySession(c) {
		return true
	}
	return models.HasPermission(c.GetString("permissions"), permission)
}

func (h *APIHandler) isRecoverySession(c *gin.Context) bool {
	return h.cfg != nil && h.cfg.GUIAdmin != "" &&
		c.GetString("username") == h.cfg.GUIAdmin && !c.GetBool("token_auth")
}

func (h *APIHandler) hasAccountAuthority(c *gin.Context, account models.AdminAccount) bool {
	return h.isRecoverySession(c) || models.PermissionsCoverAccount(c.GetString("permissions"), account)
}

func (h *APIHandler) identityFailure(c *gin.Context, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		c.JSON(http.StatusNotFound, gin.H{"error": "Account or role no longer exists. Refresh and try again."})
	case errors.Is(err, repository.ErrIdentityConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "This record changed or its name is already used. Refresh before saving."})
	case errors.Is(err, repository.ErrIdentityDenied):
		c.JSON(http.StatusForbidden, gin.H{"error": "This account change is not allowed. Refresh and check your access."})
	case errors.Is(err, repository.ErrRoleInUse):
		c.JSON(http.StatusConflict, gin.H{"error": "Assign this role's accounts to another role before deleting it."})
	case errors.Is(err, repository.ErrRoleProtected):
		c.JSON(http.StatusConflict, gin.H{"error": "Built-in roles can be edited, but cannot be deleted."})
	default:
		zlog.Error().Err(err).Msg("Identity operation failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "The change could not be saved. Try again."})
	}
}

// canManageAccount authorizes the caller against the target's current state
// and returns that snapshot. Mutations must pass it to the repository, which
// rejects the change if the target changed after this check.
func (h *APIHandler) canManageAccount(c *gin.Context, username string) (*models.AdminAccount, bool) {
	if h.identityRepo == nil {
		return nil, true
	}
	admin, err := h.pgRepo.GetAdmin(username)
	if err != nil || admin == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found."})
		return nil, false
	}
	if !h.hasAccountAuthority(c, *admin) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You cannot manage an account with permissions you do not hold."})
		return nil, false
	}
	return admin, true
}

// adminMutation binds a change to the authorized target snapshot.
func (h *APIHandler) adminMutation(c *gin.Context, target models.AdminAccount) models.AdminMutation {
	return models.AdminMutation{Expected: target, Actor: c.GetString("username"), RecoveryAdmin: h.cfg.GUIAdmin}
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
	target, allowed := h.canManageAccount(c, req.Username)
	if !allowed {
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
	// Clearing an Entra override lets the next sign-in apply whichever role the
	// directory maps, which this request cannot check. Only callers who may
	// grant every permission may do that.
	if target.AuthSource == "entra" && target.EntraRoleOverride && !req.Override && !h.isRecoverySession(c) {
		if _, err := h.validatePermissionSubset(models.AllPermissions(), c.GetString("permissions")); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only an administrator holding every permission can return this account to its Microsoft Entra role."})
			return
		}
	}
	assignment := models.RoleAssignment{
		AdminMutation: h.adminMutation(c, *target),
		RoleID:        role.ID,
		RoleRevision:  role.Revision,
		Override:      req.Override,
	}
	if err := h.identityRepo.AssignManagedAdminRole(c.Request.Context(), assignment); err != nil {
		h.identityFailure(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}
