package api

import (
	"bytes"
	"html"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"blocklist/internal/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupAuthTest() (*APIHandler, *MockAuthService, *MockPostgresRepo) {
	h, _, pg, auth, _ := setupTest()
	return h, auth, pg
}

func TestAPIHandler_EntraDisplayNamePreservesIdentity(t *testing.T) {
	const key = "entra:11111111-1111-1111-1111-111111111111:22222222-2222-2222-2222-222222222222"
	for _, tc := range []struct {
		name, source, upn, label string
	}{
		{name: "entra upn", source: "entra", upn: "person@example.test", label: "person@example.test"},
		{name: "renamed upn", source: "entra", upn: "renamed@example.test", label: "renamed@example.test"},
		{
			name: "escaped upn", source: "entra", upn: `<script>alert("x")</script>@example.test`,
			label: `<script>alert("x")</script>@example.test`,
		},
		{name: "missing upn", source: "entra", label: key},
		{name: "local keeps username", source: "local", upn: "ignored@example.test", label: key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, pg, _, _ := setupTest()
			h.identityRepo = identityTestRepository{}
			account := models.AdminAccount{
				Username: key, AuthSource: tc.source, EntraUPN: tc.upn,
				Permissions: "gui_read,view_admins,manage_admins",
			}
			pg.On("GetAdmin", key).Return(&account, nil).Once()
			pg.On("GetAllAdmins").Return([]models.AdminAccount{account}, nil).Once()
			w := httptest.NewRecorder()
			_, r := setupHTMLTest(w)
			r.Use(sessions.Sessions("session", cookie.NewStore([]byte("synthetic-session-key"))))
			r.Use(func(c *gin.Context) {
				session := sessions.Default(c)
				session.Set("logged_in", true)
				session.Set("username", key)
				session.Set("client_ip", "127.0.0.1")
				// A cached label must not override the current database value.
				session.Set("display_username", "stale@example.test")
			})
			r.GET("/admin_management", h.AuthMiddleware(), func(c *gin.Context) {
				assert.Equal(t, key, c.GetString("username"))
				assert.Equal(t, key, sessions.Default(c).Get("username"))
				assert.Equal(t, account.Permissions, c.GetString("permissions"))
				h.AdminManagement(c)
			})
			req := httptest.NewRequest(http.MethodGet, "/admin_management", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			body := w.Body.String()
			label := template.HTMLEscapeString(tc.label)
			assert.Contains(t, body, `<strong title="`+label+`">`+label+`</strong>`)
			assert.Contains(t, body, `<strong class="account-name">`+label+`</strong>`)
			assert.Contains(t, body, `data-username="`+key+`"`)
			assert.Contains(t, body, `data-account-name="`+label+`"`)
			assert.Contains(t, body, `Role for `+label+`</label>`)
			assert.NotContains(t, body, "stale@example.test")
			assert.NotContains(t, body, `<script>alert("x")</script>`)
			pg.AssertExpectations(t)
		})
	}
}

func TestLoginTemplatePreservesNextQueryComponent(t *testing.T) {
	login, err := template.ParseFiles("../../cmd/server/templates/login.html")
	if err != nil {
		t.Fatal(err)
	}
	attributes := regexp.MustCompile(`(?:href|action)="([^"]*)"`)
	tests := []struct {
		name string
		next string
	}{
		{name: "simple path", next: "/settings"},
		{name: "query and fragment", next: "/settings?tab=webhooks&sort=desc#keys"},
		{name: "reserved and unicode", next: "/dashboard?q=Grüße + %26&next=/roles#details"},
	}
	for _, tt := range tests {
		for _, method := range []string{"local", "entra"} {
			t.Run(tt.name+"/"+method, func(t *testing.T) {
				var rendered bytes.Buffer
				err := login.Execute(&rendered, gin.H{
					"is_sudo": true, "entra_sudo": method == "entra", "step": "totp", "next": tt.next,
				})
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, attribute := range attributes.FindAllStringSubmatch(rendered.String(), -1) {
					location, err := url.Parse(html.UnescapeString(attribute[1]))
					if err != nil {
						t.Fatal(err)
					}
					if location.Path != "/sudo" && location.Path != "/auth/entra/login" {
						continue
					}
					found = true
					query := location.Query()
					if query.Get("next") != tt.next || len(query["next"]) != 1 || location.Fragment != "" {
						t.Fatalf("next did not round-trip: %s", location)
					}
					if strings.Contains(location.RawQuery, "&sort=") {
						t.Fatalf("next escaped its query component: %s", location)
					}
				}
				if !found {
					t.Fatal("missing reauthentication destination")
				}
			})
		}
	}
}

func TestAPIHandler_Login_Success(t *testing.T) {
	h, auth, pg := setupAuthTest()

	// Mock DB lookups
	pg.On("GetAdmin", "admin").Return(&models.AdminAccount{
		Username: "admin",
		Role:     "admin",
		Token:    "secret",
	}, nil)
	pg.On("LogAction", "admin", "LOGIN_SUCCESS", mock.Anything, "").Return(nil)

	// Mock Auth Service
	auth.On("CheckAuth", "admin", "password", "123456").Return(true)

	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	r.POST("/login", h.Login)

	w := httptest.NewRecorder()
	form := url.Values{}
	form.Add("username", "admin")
	form.Add("password", "password")
	form.Add("totp", "123456")
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code) // Redirect to dashboard
	assert.Equal(t, "/dashboard", w.Header().Get("Location"))
}

func TestAPIHandler_Login_Failure(t *testing.T) {
	h, auth, pg := setupAuthTest()

	pg.On("GetAdmin", "admin").Return(&models.AdminAccount{Username: "admin"}, nil)
	pg.On("LogAction", "admin", "LOGIN_FAILURE", mock.Anything, mock.Anything).Return(nil)
	auth.On("CheckAuth", "admin", "wrong", "000000").Return(false)

	w := httptest.NewRecorder()
	_, r := setupHTMLTest(w)

	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	r.POST("/login", h.Login)
	form := url.Values{}
	form.Add("username", "admin")
	form.Add("password", "wrong")
	form.Add("totp", "000000")
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code) // Renders login page with error
	assert.Contains(t, w.Body.String(), "Invalid credentials")
}

func TestAPIHandler_Login_RejectsCrossAccountTOTPEnrollment(t *testing.T) {
	h, _, pg := setupAuthTest()

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Blocklist App",
		AccountName: "attacker",
	})
	assert.NoError(t, err)
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	assert.NoError(t, err)

	pg.On("GetAdmin", "victim").Return(&models.AdminAccount{
		Username: "victim",
	}, nil).Maybe()
	pg.On("UpdateAdminToken", "victim", key.Secret()).Return(nil).Maybe()
	pg.On("LogAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	w := httptest.NewRecorder()
	_, r := setupHTMLTest(w)
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	r.POST("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("pending_auth_user", "attacker")
		session.Set("pending_auth_verified", true)
		session.Set("pending_totp_secret", key.Secret())
		h.Login(c)
	})

	form := url.Values{}
	form.Add("username", "victim")
	form.Add("password", "bypass-multistep-check")
	form.Add("totp", code)
	form.Add("setup_secret", key.Secret())
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Session expired or invalid setup attempt")
	pg.AssertNotCalled(t, "UpdateAdminToken", "victim", key.Secret())
}

// TestAPIHandler_VerifySudo_RejectsEmptyTOTPSecret is a regression test for the
// TOTP empty-secret bypass: an account that has not enrolled TOTP (Token == "")
// must not be able to elevate to sudo, because totp.Validate against an empty
// secret accepts the attacker-computable empty-key code.
func TestAPIHandler_VerifySudo_RejectsEmptyTOTPSecret(t *testing.T) {
	h, _, pg := setupAuthTest()

	// Admin exists but has NOT enrolled a TOTP secret.
	pg.On("GetAdmin", "admin").Return(&models.AdminAccount{
		Username: "admin",
		Role:     "admin",
		Token:    "",
	}, nil)

	// The empty secret is public, so an attacker can compute the current code.
	code, err := totp.GenerateCode("", time.Now())
	assert.NoError(t, err)

	r := gin.New()
	r.SetFuncMap(GetFuncMap())
	r.LoadHTMLGlob("../../cmd/server/templates/*")
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	r.POST("/sudo", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("username", "admin")
		_ = session.Save()
		c.Set("username", "admin")
		h.VerifySudo(c)
	})

	form := url.Values{}
	form.Add("totp", code)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/sudo", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	// Must NOT grant sudo (no redirect); should re-render the TOTP page with error.
	assert.NotEqual(t, http.StatusFound, w.Code, "empty-secret TOTP must not grant sudo elevation")
	assert.Contains(t, w.Body.String(), "Invalid TOTP code")
}

func TestAPIHandler_Logout(t *testing.T) {
	h, _, _ := setupAuthTest()

	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	r.GET("/logout", h.Logout)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/logout", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestAPIHandler_CreateAPIToken(t *testing.T) {
	h, _, pg := setupAuthTest()

	pg.On("CreateAPIToken", mock.Anything).Return(nil)
	pg.On("GetAPITokens", "admin").Return([]models.APIToken{}, nil)
	pg.On("LogAction", "admin", "CREATE_TOKEN", "New Token", mock.Anything).Return(nil)

	w := httptest.NewRecorder()
	_, r := setupHTMLTest(w)

	r.POST("/api/tokens", func(c *gin.Context) {
		c.Set("username", "admin")
		c.Set("role", "admin")
		c.Set("permissions", "all")
		h.CreateAPIToken(c)
	})

	form := url.Values{}
	form.Add("name", "New Token")
	form.Add("permissions", "block_ips")
	req, _ := http.NewRequest("POST", "/api/tokens", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("HX-Trigger"), "newToken")
}

func TestAPIHandler_CreateAPIToken_InsufficientPerms(t *testing.T) {
	h, _, _ := setupAuthTest()

	w := httptest.NewRecorder()
	_, r := setupHTMLTest(w)

	r.POST("/api/tokens", func(c *gin.Context) {
		c.Set("username", "user1")
		c.Set("role", "operator")
		c.Set("permissions", "view_ips") // User only has view_ips
		h.CreateAPIToken(c)
	})

	form := url.Values{}
	form.Add("name", "New Token")
	form.Add("permissions", "block_ips") // Requested block_ips
	req, _ := http.NewRequest("POST", "/api/tokens", bytes.NewBufferString(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions to grant: block_ips")
}

func TestAPIHandler_RevokeAPIToken(t *testing.T) {
	h, _, pgRepo, _, _ := setupTest()

	pgRepo.On("DeleteAPITokenByID", 123).Return(nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "123"}}
	c.Request, _ = http.NewRequest("DELETE", "/api/tokens/123", nil)
	// Add permission for admin revoke logic
	c.Set("permissions", "manage_global_tokens")
	c.Set("username", "admin")
	pgRepo.On("LogAction", "admin", "ADMIN_REVOKE_TOKEN", "123", mock.Anything).Return(nil)
	h.AdminRevokeAPIToken(c)

	assert.Equal(t, http.StatusOK, w.Code)
}
