package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KernelFreeze/aether-auth/internal/config"
	"github.com/KernelFreeze/aether-auth/internal/database"
	"github.com/KernelFreeze/aether-auth/internal/routes"
	"github.com/KernelFreeze/aether-auth/internal/server"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// init dbs
	_ = database.InitDatabases(database.NewPostgresConfig(), database.RedisConfig(cfg.Redis))

	// Initialize PostgreSQL
	db := database.GetPostgres()
	sqlDb, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get DB connection: %v", err)
	}
	defer closeResource("PostgreSQL", sqlDb.Close)

	// Initialize Redis
	redisClient := database.GetRedis()
	defer closeResource("Redis", redisClient.Close)

	// Setup router
	router := routes.SetupRouter(db)

	// Use the server abstraction
	srv := server.NewServer(router)

	// Handle graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-quit
		fmt.Println("Shutting down server...")

		// Create shutdown context with a timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Shutdown services gracefully
		if err := srv.Shutdown(ctx); err != nil {
			log.Fatalf("Server shutdown failed: %v", err)
		}

		fmt.Println("Server gracefully stopped")
	}()

	// Start server
	port := cfg.Server.Port
	if err := srv.Start(port); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func closeResource(name string, close func() error) {
	if err := close(); err != nil {
		log.Printf("Failed to close %s: %v", name, err)
	}
}
