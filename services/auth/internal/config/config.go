package config

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type JWTConfig struct {
	Secret     string `yaml:"secret" env:"JWT_SECRET"`
	ExpMinutes int    `yaml:"exp_minutes" env:"JWT_EXP_MINUTES"`
}

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
	JWT      JWTConfig      `yaml:"jwt"`
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	if err := cleanenv.ReadConfig("./auth/internal/config/config.yaml", cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
