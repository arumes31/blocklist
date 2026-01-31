package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
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

func main() {
	// 0. Setup Structured Logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zlog.Logger = zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	cfg := config.Load()
	if !cfg.LogWeb {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	zlog.Info().Msg("Starting Blocklist Go Server")

	// Run Migrations
	d, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to create iofs source")
	}
	m, err := migrate.NewWithSourceInstance("iofs", d, cfg.PostgresURL)
	if err == nil {
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			zlog.Error().Err(err).Msg("Migration error")
		} else {
			zlog.Info().Msg("Database migrations applied successfully")
		}
	} else {
		zlog.Error().Err(err).Msg("Failed to initialize migrations")
	}

	// 1. Initialize Repositories
	redisRepo := repository.NewRedisRepository(cfg.RedisHost, cfg.RedisPort, cfg.RedisDB)
	pgRepo, err := repository.NewPostgresRepository(cfg.PostgresURL)
	if err != nil {
		zlog.Warn().Err(err).Msg("Failed to connect to Postgres. Persistent features may be limited.")
	}

	// 2. Initialize Services
	authService := service.NewAuthService(pgRepo, redisRepo)
	ipService := service.NewIPService(cfg, redisRepo, pgRepo)
	webhookService := service.NewWebhookService(pgRepo)
	scheduler := service.NewSchedulerService(redisRepo)
	geoUpdater := service.NewGeoIPService(cfg)

	// 3. Start Schedulers
	scheduler.Start()
	geoUpdater.Start()

	// 4. Initialize WebSocket Hub
	hub := api.NewHub()
	go hub.Run()

	// 5. Setup Gin
	if !cfg.LogWeb {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

	// Improvement: Reverse Proxy & Cloudflare Support
	if cfg.TrustedProxies != "" {
		proxies := strings.Split(cfg.TrustedProxies, ",")
		for i := range proxies {
			proxies[i] = strings.TrimSpace(proxies[i])
		}
		if err := r.SetTrustedProxies(proxies); err != nil {
			zlog.Error().Err(err).Msg("Failed to set trusted proxies")
		}
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
	store, err := redis.NewStore(10, "tcp", fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort), "", cfg.SecretKey)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to create session store")
	}
	// Harden cookie settings
	store.Options(sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	r.Use(sessions.Sessions("blocklist_session", store))

	// Rate Limiting
	rate := limiter.Rate{
		Period: 1,
		Limit:  200,
	}
	limiterClient := rdb.NewClient(&rdb.Options{
		Addr: fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort),
		DB:   cfg.RedisLimDB,
	})
	limitStore, err := sredis.NewStoreWithOptions(limiterClient, limiter.StoreOptions{
		Prefix: "limiter_go",
	})
	if err != nil {
		zlog.Fatal().Err(err).Msg("Failed to create limiter store")
	}
	rateLimiter := limiter.New(limitStore, rate)
	r.Use(mgin.NewMiddleware(rateLimiter))

	// Load Templates from embed.FS
	templ := template.Must(template.New("").Funcs(map[string]interface{}{
		"lower": strings.ToLower,
	}).ParseFS(templateFS, "templates/*.html"))
	r.SetHTMLTemplate(templ)

	// Security headers middleware
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
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
		origin := c.GetHeader("Origin")
		ref := c.GetHeader("Referer")
		host := c.Request.Host
		ok := false
		if origin != "" {
			if u, err := url.Parse(origin); err == nil && u.Host == host { ok = true }
		}
		if !ok && ref != "" {
			if u, err := url.Parse(ref); err == nil && u.Host == host { ok = true }
		}
		if !ok {
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

	// 6. Initialize API Handler
	handler := api.NewAPIHandler(cfg, redisRepo, pgRepo, authService, ipService, hub, webhookService)
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