package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"golang.org/x/crypto/hkdf"

	"blocklist/internal/api"
	"blocklist/internal/app"
	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/tasks"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	rdb "github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	sredis "github.com/ulule/limiter/v3/drivers/store/redis"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

//go:embed migrations/*
var migrationsFS embed.FS

// CensorWriter masks sensitive information in logs using regex.
type CensorWriter struct {
	io.Writer
	re *regexp.Regexp
}

// Write implements the io.Writer interface and censors sensitive keys.
func (w *CensorWriter) Write(p []byte) (n int, err error) {
	// Simple regex to mask common sensitive keys in JSON/Text logs
	// matches: "password":"...", "secret":"...", etc.
	censored := w.re.ReplaceAll(p, []byte(`${1}${2}[CENSORED]`))
	// Honor the io.Writer contract: report bytes consumed from the caller
	// (len(p)), not the post-censoring length, which is typically shorter.
	if _, err := w.Writer.Write(censored); err != nil {
		return 0, err
	}
	return len(p), nil
}

func main() {
	cfg := config.Load()

	// 0. Setup Structured Logging
	setupLogger(cfg)

	// 1. Derive Session Keys
	authKey, blockKey := deriveSessionKeys(cfg.SecretKey)

	// 2. Run Database Migrations
	runMigrations(cfg.PostgresURL)

	// 3. Bootstrap shared state
	a, err := app.Bootstrap(cfg)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to bootstrap app")
	}
	defer a.Close()

	// 4. Seed Admin User if missing
	seedAdminUser(a, cfg)

	// 5. Start Schedulers & Task Workers (Optional)
	asynqServer, asynqScheduler := initBackgroundWorkers(a, cfg)

	// 6. Initialize WebSocket Hub
	hub := api.NewHub(a.RedisRepo.GetClient())
	go hub.Run()

	// 7. Setup Gin Router
	r := setupRouter(cfg, a, hub, authKey, blockKey)

	// 8. Run Server with Graceful Shutdown
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second, // Protect against Slowloris attacks
	}

	go func() {
		zlog.Info().Str("port", cfg.Port).Msg("Starting Blocklist Go Server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zlog.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	zlog.Info().Msg("Shutting down server...")

	// 1. Stop Asynq components first if they were started
	if asynqScheduler != nil {
		asynqScheduler.Shutdown()
	}
	if asynqServer != nil {
		asynqServer.Shutdown()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 2. Shutdown HTTP Server
	if err := srv.Shutdown(ctx); err != nil {
		zlog.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	// Shared state (a) is released by the deferred a.Close() registered above.
	zlog.Info().Msg("Server exiting")
}

// setupLogger initializes the structured logger with censorship.
func setupLogger(cfg *config.Config) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	censorRE := regexp.MustCompile(`(?i)(password|secret|token)(["':\s=]*[:=][\s"':=]*|\s*["']\s*)([^"'\s,{}]+)`)
	cw := &CensorWriter{
		Writer: zerolog.ConsoleWriter{Out: os.Stderr},
		re:     censorRE,
	}
	zlog.Logger = zerolog.New(cw).With().Timestamp().Logger()

	if !cfg.LogWeb {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

// deriveSessionKeys uses HKDF to derive stable keys for session encryption and authentication.
func deriveSessionKeys(secretKey string) (authKey, blockKey []byte) {
	// Refuse to start with a default or weak SECRET_KEY. The session
	// authentication/encryption keys are HKDF-derived from it, so a known or
	// low-entropy secret allows an attacker to forge valid session cookies
	// (full authentication bypass). Fail closed instead of booting insecurely.
	if secretKey == "" || secretKey == "change-me" {
		zlog.Fatal().Msg("SECRET_KEY is unset or using the insecure default 'change-me'. Set a strong, random SECRET_KEY (32+ characters) before starting.")
	}
	if len(secretKey) < 16 {
		zlog.Fatal().Msg("SECRET_KEY is too short. Use at least 16 characters (32+ recommended) of high-entropy randomness.")
	}

	// Ensure SECRET_KEY is stable and correctly sized for AES-256 (32 bytes)
	// We use HKDF to derive two distinct keys from the single input secret.

	// 1. Auth Key (Context: "blocklist_auth_key")
	authKDF := hkdf.New(sha256.New, []byte(secretKey), nil, []byte("blocklist_auth_key"))
	authKey = make([]byte, 32)
	if _, err := io.ReadFull(authKDF, authKey); err != nil {
		zlog.Fatal().Err(err).Msg("Failed to derive auth key")
	}

	// 2. Encryption Key (Context: "blocklist_encryption_key")
	encKDF := hkdf.New(sha256.New, []byte(secretKey), nil, []byte("blocklist_encryption_key"))
	blockKey = make([]byte, 32)
	if _, err := io.ReadFull(encKDF, blockKey); err != nil {
		zlog.Fatal().Err(err).Msg("Failed to derive encryption key")
	}

	return authKey, blockKey
}

// runMigrations applies database schema changes using embedded migrations.
func runMigrations(postgresURL string) {
	d, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to create iofs source")
	}
	m, err := migrate.NewWithSourceInstance("iofs", d, postgresURL)
	if err == nil {
		version, dirty, err := m.Version()
		if err != nil && err != migrate.ErrNilVersion {
			zlog.Error().Err(err).Msg("Failed to get migration version")
		} else {
			zlog.Info().Uint("version", version).Bool("dirty", dirty).Msg("Current database version")
		}

		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			zlog.Error().Err(err).Msg("Migration error")
		} else if err == migrate.ErrNoChange {
			zlog.Info().Msg("Database is up to date (no migrations needed)")
		} else {
			zlog.Info().Msg("Database migrations applied successfully")
		}
	} else {
		zlog.Error().Err(err).Msg("Failed to initialize migrations")
	}
}

// seedAdminUser creates the initial administrator account if it doesn't exist.
func seedAdminUser(a *app.App, cfg *config.Config) {
	if a.PgRepo != nil && cfg.GUIAdmin != "" {
		admin, _ := a.PgRepo.GetAdmin(cfg.GUIAdmin)
		if admin == nil {
			if cfg.GUIPassword == "" {
				zlog.Fatal().Msg("GUIPassword environment variable must be set for initial administrator seeding.")
			}
			zlog.Info().Str("username", cfg.GUIAdmin).Msg("Seeding initial admin user")
			hash, _ := a.AuthService.HashPassword(cfg.GUIPassword)
			err := a.PgRepo.CreateAdmin(models.AdminAccount{
				Username:     cfg.GUIAdmin,
				PasswordHash: hash,
				Token:        cfg.GUIToken,
				Role:         "admin",
				Permissions:  "gui_read,gui_write,block_ips,unblock_ips,manage_whitelist,manage_excluded,manage_webhooks,manage_api_tokens,manage_global_tokens,manage_admins,view_stats,view_audit_logs,export_data,whitelist_ips,view_ips",
			})
			if err != nil {
				zlog.Error().Err(err).Msg("Failed to seed admin user")
			}
		}
	}
}

// initBackgroundWorkers starts the Asynq server and scheduler for background tasks.
func initBackgroundWorkers(a *app.App, cfg *config.Config) (*asynq.Server, *asynq.Scheduler) {
	var asynqServer *asynq.Server
	var asynqScheduler *asynq.Scheduler

	if cfg.RunWorkerInProcess {
		zlog.Info().Msg("Starting background worker in-process")

		a.Scheduler.Start()
		a.GeoUpdater.Start()

		// Initialize Asynq Server
		asynqServer = asynq.NewServer(
			a.RedisOpts,
			asynq.Config{
				Concurrency: 10,
				Queues: map[string]int{
					"default": 5,
					"low":     2,
				},
			},
		)

		asynqMux := asynq.NewServeMux()
		asynqMux.Handle(tasks.TypeWebhookDelivery, tasks.NewWebhookTaskHandler(a.PgRepo))
		asynqMux.Handle(tasks.TypeGeoIPUpdate, tasks.NewGeoIPTaskHandler(cfg, a.IPService))

		go func() {
			if err := asynqServer.Run(asynqMux); err != nil {
				zlog.Fatal().Err(err).Msg("Failed to run asynq server")
			}
		}()

		// Initialize Asynq Scheduler for periodic tasks
		asynqScheduler = asynq.NewScheduler(a.RedisOpts, &asynq.SchedulerOpts{})

		// Schedule GeoIP updates every 72 hours
		cityTask, _ := tasks.NewGeoIPUpdateTask("GeoLite2-City")
		asnTask, _ := tasks.NewGeoIPUpdateTask("GeoLite2-ASN")

		if _, err := asynqScheduler.Register("@every 72h", cityTask); err != nil {
			zlog.Error().Err(err).Msg("Failed to schedule GeoLite2-City update")
		}
		if _, err := asynqScheduler.Register("@every 72h", asnTask); err != nil {
			zlog.Error().Err(err).Msg("Failed to schedule GeoLite2-ASN update")
		}

		// Schedule External Source refresh every 6 hours
		if _, err := asynqScheduler.Register("@every 6h", tasks.NewRefreshExternalSourcesTask()); err != nil {
			zlog.Error().Err(err).Msg("Failed to schedule external source refresh")
		}

		go func() {
			if err := asynqScheduler.Run(); err != nil {
				zlog.Fatal().Err(err).Msg("Failed to run asynq scheduler")
			}
		}()
	} else {
		zlog.Info().Msg("Background worker disabled (external worker expected)")
	}

	return asynqServer, asynqScheduler
}

// setupRouter configures the Gin engine with all middleware and routes.
func setupRouter(cfg *config.Config, a *app.App, hub *api.Hub, authKey, blockKey []byte) *gin.Engine {
	if !cfg.LogWeb {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

	// Configure Trusted Proxies
	setupTrustedProxies(r, cfg)

	// Force HTTPS (Improvement)
	if cfg.ForceHTTPS {
		r.Use(httpsRedirectMiddleware())
	}

	// Sessions
	setupSessions(r, cfg, authKey, blockKey)

	// Rate Limiting
	mainLimiter, loginLimiter, webhookLimiter := setupRateLimiters(cfg)

	// Load Templates
	setupTemplates(r)

	// Security Headers with CSP and Nonce
	r.Use(securityHeadersMiddleware(cfg))

	// Basic CSRF Protection
	r.Use(csrfProtectionMiddleware())

	// Serve Static Files
	setupStaticFiles(r)

	// Serve favicon
	setupFavicon(r)

	// Initialize API Handler
	handler := api.NewAPIHandler(&api.HandlerOptions{
		Config:                cfg,
		RedisRepo:             a.RedisRepo,
		PgRepo:                a.PgRepo,
		AuthService:           a.AuthService,
		IPService:             a.IPService,
		Hub:                   hub,
		WebhookService:        a.WebhookService,
		ExternalSourceService: a.ExternalSourceService,
		MainLimiter:           mainLimiter,
		LoginLimiter:          loginLimiter,
		WebhookLimiter:        webhookLimiter,
	})
	handler.RegisterRoutes(r)

	return r
}

func setupTrustedProxies(r *gin.Engine, cfg *config.Config) {
	// Configure Trusted Proxies to handle requests from Docker, Tailscale, and private networks.
	// This is critical for correct IP detection behind reverse proxies.
	trustedProxies := []string{"127.0.0.1", "172.16.0.0/12", "100.64.0.0/10", "10.0.0.0/8", "192.168.0.0/16"}
	if cfg.TrustedProxies != "" {
		p := strings.Split(cfg.TrustedProxies, ",")
		for i := range p {
			trustedProxies = append(trustedProxies, strings.TrimSpace(p[i]))
		}
	}
	if err := r.SetTrustedProxies(trustedProxies); err != nil {
		zlog.Error().Err(err).Msg("Failed to set trusted proxies")
	}
}

func httpsRedirectMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Header.Get("X-Forwarded-Proto") != "https" && c.Request.TLS == nil {
			// Use 308 Permanent Redirect to preserve non-GET methods (compliance/robustness)
			target := "https://" + c.Request.Host + c.Request.RequestURI
			c.Redirect(http.StatusPermanentRedirect, target)
			c.Abort()
			return
		}
		c.Next()
	}
}

func setupSessions(r *gin.Engine, cfg *config.Config, authKey, blockKey []byte) {
	store, err := redis.NewStore(10, "tcp", fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort), "", cfg.RedisPassword, authKey, blockKey)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to create session store")
	}

	// Harden cookie settings
	sameSite := http.SameSiteLaxMode
	if cfg.SameSiteStrict {
		sameSite = http.SameSiteStrictMode
	}

	// Automatically enable Secure cookies if HTTPS is forced.
	cookieSecure := cfg.CookieSecure
	if cfg.ForceHTTPS {
		cookieSecure = true
	}

	store.Options(sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: sameSite,
		MaxAge:   86400 * 7, // 1 week
	})
	r.Use(sessions.Sessions("blocklist_session", store))
}

func setupRateLimiters(cfg *config.Config) (main, login, webhook gin.HandlerFunc) {
	createLimiter := func(limit int, period int, prefix string) gin.HandlerFunc {
		rate := limiter.Rate{
			Period: time.Duration(period) * time.Second,
			Limit:  int64(limit),
		}
		limiterClient := rdb.NewClient(&rdb.Options{
			Addr:     fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort),
			Password: cfg.RedisPassword,
			DB:       cfg.RedisLimDB,
		})
		limitStore, err := sredis.NewStoreWithOptions(limiterClient, limiter.StoreOptions{
			Prefix: prefix,
		})
		if err != nil {
			zlog.Fatal().Err(err).Msgf("Failed to create limiter store: %s", prefix)
		}
		return mgin.NewMiddleware(limiter.New(limitStore, rate))
	}

	main = createLimiter(cfg.RateLimit, cfg.RatePeriod, "limiter_main")
	login = createLimiter(cfg.RateLimitLogin, cfg.RatePeriod, "limiter_login")
	webhook = createLimiter(cfg.RateLimitWebhook, cfg.RatePeriod, "limiter_webhook")
	return
}

func setupTemplates(r *gin.Engine) {
	// Load Templates: Prefer filesystem for development/runtime updates, fallback to embed.FS
	funcMap := api.GetFuncMap()

	var templ *template.Template
	if _, err := os.Stat("cmd/server/templates"); err == nil {
		templ = template.Must(template.New("").Funcs(funcMap).ParseGlob("cmd/server/templates/*.html"))
		zlog.Info().Msg("Templates loaded from filesystem")
	} else {
		templ = template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))
		zlog.Info().Msg("Templates loaded from embed.FS")
	}
	r.SetHTMLTemplate(templ)
}

func securityHeadersMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate Nonce
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			zlog.Error().Err(err).Msg("Failed to generate nonce")
		}
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)

		// Set in context for templates
		c.Set("nonce", nonce)

		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "same-origin")

		// Strict Transport Security (HSTS)
		if cfg.UseCloudflare || c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		// Content Security Policy (CSP)
		csp := fmt.Sprintf("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-%s'; script-src-attr 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; frame-ancestors 'none'; object-src 'none'; base-uri 'none';", nonce)
		c.Header("Content-Security-Policy", csp)

		c.Next()
	}
}

func csrfProtectionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		// Bypass CSRF for API requests using Bearer tokens
		if strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
			c.Next()
			return
		}

		origin := c.GetHeader("Origin")
		ref := c.GetHeader("Referer")
		host := c.Request.Host
		ok := false

		// Handle cases where Origin might be "null" due to browser privacy settings
		if origin != "" && origin != "null" {
			if u, err := url.Parse(origin); err == nil && u.Host == host {
				ok = true
			}
		}

		// Fallback to Referer check
		if !ok && ref != "" {
			if u, err := url.Parse(ref); err == nil && u.Host == host {
				ok = true
			}
		}

		// In case of non-browser clients (like curl) that don't send Origin/Referer
		// but aren't using session cookies. Note: AuthMiddleware will still verify credentials.
		if !ok && origin == "" && ref == "" {
			// Check if there's a session cookie. If not, it's likely a non-browser API client.
			session := sessions.Default(c)
			if session.Get("logged_in") == nil {
				ok = true
			}
		}

		if !ok {
			zlog.Warn().Str("origin", origin).Str("referer", ref).Str("host", host).Msg("CSRF check failed")
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

func setupStaticFiles(r *gin.Engine) {
	serveStatic := func(urlPath, diskPath, embedPath string) {
		if _, err := os.Stat(diskPath); err == nil {
			r.Static(urlPath, diskPath)
			zlog.Info().Str("url", urlPath).Str("disk", diskPath).Msg("Serving static files from disk")
		} else {
			sub, _ := fs.Sub(staticFS, embedPath)
			r.StaticFS(urlPath, http.FS(sub))
			zlog.Info().Str("url", urlPath).Str("embed", embedPath).Msg("Serving static files from embed.FS")
		}
	}

	serveStatic("/static", "cmd/server/static", "static")
	serveStatic("/js", "cmd/server/static/js", "static/js")
	serveStatic("/cd", "cmd/server/static/cd", "static/cd")
	serveStatic("/flags", "cmd/server/static/flags", "static/flags")
}

func setupFavicon(r *gin.Engine) {
	r.GET("/favicon.ico", func(c *gin.Context) {
		if data, err := os.ReadFile("cmd/server/static/cd/favicon-color.png"); err == nil {
			c.Data(http.StatusOK, "image/png", data)
			return
		}
		file, err := staticFS.ReadFile("static/cd/favicon-color.png")
		if err != nil {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, "image/png", file)
	})

}
