package frontend_oidc

import (
	"errors"
	"os"
	"time"

	"github.com/michaelquigley/cf"
)

type Config struct {
	AppUrl         string
	AppBindAddress string
	CookieDomain   string
	CookieExpires  time.Duration
	RefreshEvery   time.Duration
	BeforeExpiry   time.Duration
	CallbackPath   string
	SigningKey     string
	SecretsKey     string
	ClientId       string
	ClientSecret   string
	Pkce           bool
	Scopes         []string
	Oauth          *OAuthConfig
	OIDC           *OIDCConfig
}

type OAuthConfig struct {
	AuthUrl     string
	TokenUrl    string
	UserinfoUrl string
}

type OIDCConfig struct {
	Issuer       string
	DiscoveryUrl string
}

func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if err := cf.BindYaml(cfg, path, cf.DefaultOptions()); err != nil {
		return cfg, err
	}
	if cfg.SigningKey == "" {
		cfg.SigningKey = os.Getenv("SIGNING_KEY")
		if cfg.SigningKey == "" {
			return cfg, errors.New("missing SIGNING_KEY in environment")
		}
	}
	if cfg.SecretsKey == "" {
		cfg.SecretsKey = os.Getenv("SECRETS_KEY")
		if cfg.SecretsKey == "" {
			return cfg, errors.New("missing SECRETS_KEY in environment")
		}
	}
	if cfg.ClientId == "" {
		cfg.ClientId = os.Getenv("CLIENT_ID")
		if cfg.ClientId == "" {
			return cfg, errors.New("missing CLIENT_ID in environment")
		}
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = os.Getenv("CLIENT_SECRET")
		if cfg.ClientSecret == "" {
			return cfg, errors.New("missing CLIENT_SECRET in environment")
		}
	}
	return cfg, nil
}
