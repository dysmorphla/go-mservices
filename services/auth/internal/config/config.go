package config

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type HTTPConfig struct {
	Port string `yaml:"port" env:"HTTP_PORT"`
}

type PostgresConfig struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
	SSLMode  string `yaml:"sslmode"`
}

type Config struct {
	HTTP     HTTPConfig     `yaml:"http"`
	Postgres PostgresConfig `yaml:"postgres"`
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	if err := cleanenv.ReadConfig("./internal/config/config.yaml", cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
