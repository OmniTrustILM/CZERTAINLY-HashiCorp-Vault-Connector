package db

import (
	"errors"
	"fmt"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/config"
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	"go.uber.org/zap"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/golang-migrate/migrate/v4"
	migratepostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

var log = logger.Get()

func ConnectDB(config config.Config) (db *gorm.DB, err error) {
	dsn := fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s sslmode=%s %s", config.Database.Username, config.Database.Password, config.Database.Host, config.Database.Port, config.Database.Name, config.Database.SslMode, config.Database.Props)
	db, err = gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   config.Database.Schema + ".",
			SingularTable: false,
		}})
	return
}

func MigrateDB(config config.Config, db *gorm.DB) {
	log.Info("Migrating database")

	// Convert *gorm.DB to *sql.DB
	sqlDB, err := db.DB()
	if err != nil {
		log.Error("Unable to get *sql.DB from GORM", zap.Error(err))
		return
	}

	// Wrap the *sql.DB with the postgres driver for golang-migrate
	dbSchema := config.Database.Schema
	driver, err := migratepostgres.WithInstance(sqlDB, &migratepostgres.Config{
		MigrationsTable: fmt.Sprintf("%s_migrations", dbSchema),
	})
	if err != nil {
		log.Error("Failed to create postgres driver for migrations", zap.Error(err))
		return
	}

	// Create a new Migrate instance using the opened DB
	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		config.Database.Name,
		driver,
	)
	if err != nil {
		log.Error("Failed to create migrate instance", zap.Error(err))
		return
	}

	// Run the migrations
	if err := m.Up(); err != nil {
		// Only log if it's something other than "no change"
		if !errors.Is(err, migrate.ErrNoChange) {
			log.Error("Migration failed", zap.Error(err))
		}
	}
}
