package main

import (
	"errors"
	"os"
	"time"

	"github.com/michaelquigley/cf"
)

type Config struct {
	BaseUri       string
	ClientId      string
	ClientSecret  string
	IssuerUrl     string
	Port          int
	Scopes        []string
	Pkce          bool
	CallbackPath  string
	SigningKey    string
	SecretsKey    string
	CookieDomain  string
	CookieMaxAge  int
	CookieExpires time.Duration
	RefreshEvery  time.Duration
	BeforeExpiry  time.Duration
}

func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if err := cf.BindYaml(cfg, path, cf.DefaultOptions()); err != nil {
		return nil, err
	}
	if cfg.SigningKey == "" {
		cfg.SigningKey = os.Getenv("SIGNING_KEY")
		if cfg.SigningKey == "" {
			return nil, errors.New("missing SIGNING_KEY in environment")
		}
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
