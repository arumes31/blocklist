package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
	"embed"
	"html/template"
	"io/fs"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"

	"blocklist/internal/api"
	"blocklist/internal/config"
	"blocklist/internal/models"
	"blocklist/internal/repository"
	"blocklist/internal/service"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	sredis "github.com/ulule/limiter/v3/drivers/store/redis"
	rdb "github.com/redis/go-redis/v9"
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

	// 1. Initialize Repositories
	redisRepo := repository.NewRedisRepository(cfg.RedisHost, cfg.RedisPort, cfg.RedisPassword, cfg.RedisDB)
	if err := redisRepo.GetClient().Ping(context.Background()).Err(); err != nil {
		zlog.Fatal().Err(err).Msg("Failed to connect to Redis")
	}

	pgRepo, err := repository.NewPostgresRepository(cfg.PostgresURL)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to connect to Postgres")
	}

	// 2. Initialize Services
	authService := service.NewAuthService(pgRepo, redisRepo)
	ipService := service.NewIPService(cfg, redisRepo, pgRepo)
	webhookService := service.NewWebhookService(pgRepo, redisRepo, cfg)
	scheduler := service.NewSchedulerService(redisRepo)
	geoUpdater := service.NewGeoIPService(cfg)

	// Seed Admin User if missing
	if pgRepo != nil && cfg.GUIAdmin != "" {
		admin, _ := pgRepo.GetAdmin(cfg.GUIAdmin)
		if admin == nil {
			zlog.Info().Str("username", cfg.GUIAdmin).Msg("Seeding initial admin user")
			hash, _ := authService.HashPassword(cfg.GUIPassword)
			err := pgRepo.CreateAdmin(models.AdminAccount{
				Username:     cfg.GUIAdmin,
				PasswordHash: hash,
				Token:        cfg.GUIToken,
				Role:         "admin",
				Permissions:  "gui_read,gui_write,block_ips,unblock_ips,manage_whitelist,manage_webhooks,manage_api_tokens,manage_admins,view_stats,view_audit_logs,export_data",
			})
			if err != nil {
				zlog.Error().Err(err).Msg("Failed to seed admin user")
			}
		}
	}

	// 3. Start Schedulers
	scheduler.Start()
	geoUpdater.Start()
	webhookService.Start(context.Background())

	// 4. Initialize WebSocket Hub
	hub := api.NewHub(redisRepo.GetClient())
	go hub.Run()

	// 5. Setup Gin
	if !cfg.LogWeb {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

	// Improvement: Reverse Proxy & Cloudflare Support
	// Add common internal ranges: 127.0.0.1, Docker (172.16.0.0/12), Tailscale (100.64.0.0/10), Private (10.0.0.0/8, 192.168.0.0/16)
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

	// Sessions
	store, err := redis.NewStore(10, "tcp", fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort), "", cfg.RedisPassword, authKey, blockKey)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to create session store")
	}
	// Harden cookie settings
	store.Options(sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Temporarily false to debug proxy/TLS issues
		SameSite: http.SameSiteLaxMode,
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

	// Load Templates from embed.FS
	templ := template.Must(template.New("").Funcs(map[string]interface{}{
		"lower":    strings.ToLower,
		"replace":  strings.ReplaceAll,
		"split":    strings.Split,
		"contains": strings.Contains,
	}).ParseFS(templateFS, "templates/*.html"))
	r.SetHTMLTemplate(templ)

	// Security headers middleware
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "same-origin")
		// Relaxed CSP for inline scripts used in templates; tighten in prod as feasible
		c.Header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:")
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

	// Serve Static Files from embed.FS
	staticRoot, _ := fs.Sub(staticFS, "static")
	r.StaticFS("/static", http.FS(staticRoot))

	jsRoot, _ := fs.Sub(staticFS, "static/js")
	r.StaticFS("/js", http.FS(jsRoot))

	cdRoot, _ := fs.Sub(staticFS, "static/cd")
	r.StaticFS("/cd", http.FS(cdRoot))

	flagsRoot, _ := fs.Sub(staticFS, "static/flags")
	r.StaticFS("/flags", http.FS(flagsRoot))

	// Serve favicon
	r.GET("/favicon.ico", func(c *gin.Context) {
		file, err := staticFS.ReadFile("static/cd/favicon-color.png")
		if err != nil {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, "image/png", file)
	})

	// 6. Initialize API Handler
	handler := api.NewAPIHandler(cfg, redisRepo, pgRepo, authService, ipService, hub, webhookService)
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		zlog.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	zlog.Info().Msg("Server exiting")
}