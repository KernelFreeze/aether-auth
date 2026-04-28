// internal/database/db.go
package database

import (
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

var (
	pgDB        *gorm.DB
	redisClient *redis.Client
)

func InitDatabases(pgConfig PostgresConfig, redisConfig RedisConfig) error {
	var err error
	pgDB, err = NewPostgresConnection(pgConfig)
	if err != nil {
		return err
	}

	redisClient, err = NewRedisConnection(redisConfig)
	if err != nil {
		return err
	}
	return nil
}

func GetPostgres() *gorm.DB {
	return pgDB
}

func GetRedis() *redis.Client {
	return redisClient
}
