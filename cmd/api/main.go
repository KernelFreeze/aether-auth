package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hokamsingh/go-backend-template/internal/config"
	"github.com/hokamsingh/go-backend-template/internal/database"
	"github.com/hokamsingh/go-backend-template/internal/routes"
	"github.com/hokamsingh/go-backend-template/internal/server"
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
	defer sqlDb.Close()

	// Initialize Redis
	redisClient := database.GetRedis()
	defer redisClient.Close()

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

		redisClient.Close()
		sqlDb.Close()
		fmt.Println("Server gracefully stopped")
	}()

	// Start server
	port := cfg.Server.Port
	if err := srv.Start(port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
