package config

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type HTTPConfig struct {
	Port string `yaml:"port" env:"HTTP_PORT"`
}

type Config struct {
	HTTP HTTPConfig `yaml:"http"`
}

func LoadConfig() (*Config, error) {
	cfg := &Config{}

	if err := cleanenv.ReadConfig("config.yaml", cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
