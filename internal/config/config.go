package config

import (
	"github.com/OmniTrustILM/hashicorp-vault-connector/internal/logger"
	"os"
)

type Config struct {
	Server struct {
		Port string
	}
	Database struct {
		Name     string
		Host     string
		Port     string
		Username string
		Password string
		Props    string
		Schema   string
		SslMode  string
	}
}

var config Config

func Get() Config {
	l := logger.Get()

	config.Server.Port = os.Getenv("SERVER_PORT")
	config.Database.Host = os.Getenv("DATABASE_HOST")
	config.Database.Port = os.Getenv("DATABASE_PORT")
	config.Database.Username = os.Getenv("DATABASE_USER")
	config.Database.Password = os.Getenv("DATABASE_PASSWORD")
	config.Database.Props = os.Getenv("DATABASE_PROPS")
	config.Database.Name = os.Getenv("DATABASE_NAME")
	config.Database.Schema = os.Getenv("DATABASE_SCHEMA")
	config.Database.SslMode = os.Getenv("DATABASE_SSL_MODE")

	if config.Server.Port == "" {
		config.Server.Port = "8080"
	}

	if config.Database.Host == "" {
		config.Database.Host = "localhost"
	}

	if config.Database.Port == "" {
		config.Database.Port = "5432"
	}

	if config.Database.Schema == "" {
		config.Database.Schema = "hvault"
	}

	if config.Database.Username == "" {
		l.Fatal("DATABASE_USER is mandatory to set!")

	}

	if config.Database.Password == "" {
		l.Fatal("DATABASE_PASSWORD is mandatory to set!")
	}

	if config.Database.Name == "" {
		l.Fatal("DATABASE_NAME is mandatory to set!")
	}

	if config.Database.SslMode == "" {
		config.Database.SslMode = "require"
	}

	return config
}
