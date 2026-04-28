package scripts

import (
	"fmt"
	"log"

	"github.com/hokamsingh/go-backend-template/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Define models for migration
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Email    string `gorm:"uniqueIndex"`
	Password string
}

// Migrate function to run database migrations
func Migrate() {
	// Load from environment variables or configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}

	dsn := cfg.Database.DSN()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// AutoMigrate runs the migration
	err = db.AutoMigrate(&User{})
	if err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	fmt.Println("Migration completed successfully!")
}
