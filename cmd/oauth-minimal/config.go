package main

import (
	"errors"
	"os"

	"github.com/michaelquigley/cf"
)

type Config struct {
	BaseUrl      string
	Port         int
	CookieDomain string
	SecretsKey   string
	ClientId     string
	ClientSecret string
	AuthUrl      string
	TokenUrl     string
	UserinfoUrl  string
	Scopes       []string
}

func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if err := cf.BindYaml(cfg, path, cf.DefaultOptions()); err != nil {
		return nil, err
	}
	if cfg.SecretsKey == "" {
		cfg.SecretsKey = os.Getenv("SECRETS_KEY")
		if cfg.SecretsKey == "" {
			return nil, errors.New("missing SECRETS_KEY in environment")
		}
	}
	if cfg.ClientId == "" {
		cfg.ClientId = os.Getenv("CLIENT_ID")
		if cfg.ClientId == "" {
			return nil, errors.New("missing CLIENT_ID in environment")
		}
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = os.Getenv("CLIENT_SECRET")
		if cfg.ClientSecret == "" {
			return nil, errors.New("missing CLIENT_SECRET in environment")
		}
	}
	return cfg, nil
}
