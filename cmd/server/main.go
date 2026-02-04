package main

import (
	"context"
	"crypto/sha256"
	"embed"
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

	"blocklist/internal/api"
	"blocklist/internal/app"
	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/tasks"
	"crypto/rand"
	"encoding/base64"

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

type CensorWriter struct {
	io.Writer
	re *regexp.Regexp
}

func (w *CensorWriter) Write(p []byte) (n int, err error) {
	// Simple regex to mask common sensitive keys in JSON/Text logs
	// matches: "password":"...", "secret":"...", etc.
	censored := w.re.ReplaceAll(p, []byte(`${1}${2}[CENSORED]`))
	return w.Writer.Write(censored)
}

func main() {
	// 0. Setup Structured Logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	censorRE := regexp.MustCompile(`(?i)(password|secret|token)(["':\s]+)([^"'\s,{}]+)`)
	cw := &CensorWriter{
		Writer: zerolog.ConsoleWriter{Out: os.Stderr},
		re:     censorRE,
	}
	zlog.Logger = zerolog.New(cw).With().Timestamp().Logger()

	cfg := config.Load()

	// Ensure SECRET_KEY is stable and correctly sized for AES-256 (32 bytes)
	// We use SHA-256 to derive two distinct keys from the single input secret.
	hash := sha256.New()
	hash.Write([]byte(cfg.SecretKey))
	authKey := hash.Sum(nil) // 32 bytes for signing

	hash.Reset()
	hash.Write([]byte(cfg.SecretKey + "_encryption"))
	blockKey := hash.Sum(nil) // 32 bytes for encryption

	if !cfg.LogWeb {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	zlog.Info().Int("auth_key_len", len(authKey)).Int("block_key_len", len(blockKey)).Msg("Starting Blocklist Go Server")

	if cfg.SecretKey == "change-me" {
		zlog.Warn().Msg("SECRET_KEY is using default. Please set a 32-byte string via environment variable.")
	}

	// Run Migrations
	d, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to create iofs source")
	}
	m, err := migrate.NewWithSourceInstance("iofs", d, cfg.PostgresURL)
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

	// 1. Bootstrap shared state
	a, err := app.Bootstrap(cfg)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to bootstrap app")
	}
	defer a.Close()

	// Seed Admin User if missing
	// Seed Admin User if missing
	if a.PgRepo != nil && cfg.GUIAdmin != "" {
		admin, _ := a.PgRepo.GetAdmin(cfg.GUIAdmin)
		if admin == nil {
			zlog.Info().Str("username", cfg.GUIAdmin).Msg("Seeding initial admin user")
			hash, _ := a.AuthService.HashPassword(cfg.GUIPassword)
			err := a.PgRepo.CreateAdmin(models.AdminAccount{
				Username:     cfg.GUIAdmin,
				PasswordHash: hash,
				Token:        cfg.GUIToken,
				Role:         "admin",
				Permissions:  "gui_read,gui_write,block_ips,unblock_ips,manage_whitelist,manage_webhooks,manage_api_tokens,manage_global_tokens,manage_admins,view_stats,view_audit_logs,export_data,whitelist_ips,view_ips",
			})
			if err != nil {
				zlog.Error().Err(err).Msg("Failed to seed admin user")
			}
		}
	}

	// 3. Start Schedulers & Task Workers (Optional)
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

		go func() {
			if err := asynqScheduler.Run(); err != nil {
				zlog.Fatal().Err(err).Msg("Failed to run asynq scheduler")
			}
		}()
	} else {
		zlog.Info().Msg("Background worker disabled (external worker expected)")
	}

	// 4. Initialize WebSocket Hub
	hub := api.NewHub(a.RedisRepo.GetClient())
	go hub.Run()

	// 5. Setup Gin
	if !cfg.LogWeb {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

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

	// Optional Cloudflare Support
	if cfg.UseCloudflare {
		r.ForwardedByClientIP = true
		r.Use(func(c *gin.Context) {
			if cfIP := c.GetHeader("CF-Connecting-IP"); cfIP != "" {
				// Override RemoteAddr so c.ClientIP() returns the Cloudflare IP
				c.Request.Header.Set("X-Forwarded-For", cfIP)
			}
			c.Next()
		})
	}

	// Force HTTPS (Improvement)
	if cfg.ForceHTTPS {
		r.Use(func(c *gin.Context) {
			if c.Request.Header.Get("X-Forwarded-Proto") != "https" && c.Request.TLS == nil {
				// Use 308 Permanent Redirect to preserve non-GET methods (compliance/robustness)
				target := "https://" + c.Request.Host + c.Request.RequestURI
				c.Redirect(http.StatusPermanentRedirect, target)
				c.Abort()
				return
			}
			c.Next()
		})
	}

	// Sessions
	store, err := redis.NewStore(10, "tcp", fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort), "", cfg.RedisPassword, authKey, blockKey)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to create session store")
	}
	// Harden cookie settings
	sameSite := http.SameSiteLaxMode
	if cfg.SameSiteStrict {
		sameSite = http.SameSiteStrictMode
	}

	// Automatically enable Secure cookies if HTTPS is forced or behind Cloudflare
	cookieSecure := cfg.CookieSecure
	if cfg.ForceHTTPS || cfg.UseCloudflare {
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

	// Rate Limiting Helpers
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

	mainLimiter := createLimiter(cfg.RateLimit, cfg.RatePeriod, "limiter_main")
	loginLimiter := createLimiter(cfg.RateLimitLogin, cfg.RatePeriod, "limiter_login")
	webhookLimiter := createLimiter(cfg.RateLimitWebhook, cfg.RatePeriod, "limiter_webhook")

	// Load Templates: Prefer filesystem for development/runtime updates, fallback to embed.FS
	funcMap := template.FuncMap{
		"lower":    strings.ToLower,
		"replace":  strings.ReplaceAll,
		"split":    strings.Split,
		"contains": strings.Contains,
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
		"safeURL":  func(s string) template.URL { return template.URL(s) },
		"add":      func(a, b int) int { return a + b },
		"sub":      func(a, b int) int { return a - b },
	}

	var templ *template.Template
	if _, err := os.Stat("cmd/server/templates"); err == nil {
		templ = template.Must(template.New("").Funcs(funcMap).ParseGlob("cmd/server/templates/*.html"))
		zlog.Info().Msg("Templates loaded from filesystem")
	} else {
		templ = template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))
		zlog.Info().Msg("Templates loaded from embed.FS")
	}
	r.SetHTMLTemplate(templ)

	// Security headers middleware with CSP and Nonce
	r.Use(func(c *gin.Context) {
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
		// style-src: Allow 'unsafe-inline' to support extensive inline styles and library injections (HTMX).
		// script-src: Use nonces for <script> tags.
		// script-src-attr: Allow inline event handlers (onclick) for compatibility.
		// ws: and wss: are allowed for WebSocket connections.
		csp := fmt.Sprintf("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-%s'; script-src-attr 'self' 'unsafe-inline'; connect-src 'self' ws: wss:", nonce)
		c.Header("Content-Security-Policy", csp)

		c.Next()
	})

	// Basic CSRF: enforce same-origin on unsafe methods via Origin/Referer
	r.Use(func(c *gin.Context) {
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
	})

	// Serve Static Files: Prefer filesystem, fallback to embed.FS
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

	// Serve favicon
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

	// 6. Initialize API Handler
	handler := api.NewAPIHandler(cfg, a.RedisRepo, a.PgRepo, a.AuthService, a.IPService, hub, a.WebhookService)
	handler.SetLimiters(mainLimiter, loginLimiter, webhookLimiter)
	handler.RegisterRoutes(r)

	// 7. Run Server with Graceful Shutdown
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
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

	zlog.Info().Msg("Server exiting")
}
