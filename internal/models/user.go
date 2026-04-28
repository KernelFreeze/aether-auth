package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email     string `gorm:"uniqueIndex;not null"`
	Password  string `gorm:"not null"`
	FirstName string
	LastName  string
	Active    bool `gorm:"default:true"`
	LastLogin time.Time
}
