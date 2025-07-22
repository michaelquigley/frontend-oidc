package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/michaelquigley/cf"
	frontend_oidc "github.com/michaelquigley/frontend-oidc"
	"github.com/michaelquigley/pfxlog"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const cookieName = "oidc-session"

func init() {
	pfxlog.GlobalInit(slog.LevelInfo, pfxlog.DefaultOptions().SetTrimPrefix("git.hq.quigley.com/research/"))
}

var cfg *frontend_oidc.Config
var provider rp.RelyingParty
var secretsKey []byte

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: oidc-session <configPath>")
		os.Exit(1)
	}

	var err error
	cfg, err = frontend_oidc.LoadConfig(os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println(cf.Dump(cfg, cf.DefaultOptions()))

	secretsKey, err = frontend_oidc.DeriveKey(cfg.SecretsKey, 32)
	if err != nil {
		panic(err)
	}

	redirectUri := fmt.Sprintf("%v%v", cfg.AppUrl, cfg.CallbackPath)
	cookieHandler := httphelper.NewCookieHandler([]byte(cfg.SigningKey), secretsKey, httphelper.WithUnsecure())
	providerOptions := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithLogger(pfxlog.Logger().Logger),
		rp.WithSigningAlgsFromDiscovery(),
	}
	if cfg.Pkce {
		providerOptions = append(providerOptions, rp.WithPKCE(cookieHandler))
	}
	provider, err = rp.NewRelyingPartyOIDC(
		context.TODO(),
		cfg.OIDC.Issuer,
		cfg.ClientId,
		cfg.ClientSecret,
		redirectUri,
		cfg.Scopes,
		providerOptions...,
	)
	if err != nil {
		panic(err)
	}

	state := func() string { return uuid.New().String() }
	urlOptions := []rp.URLParamOpt{
		rp.WithPromptURLParam("consent"),
		rp.WithResponseModeURLParam("query"),
		rp.WithURLParam("access_type", "offline"),
	}
	http.Handle("/login", rp.AuthURLHandler(state, provider, urlOptions...))

	http.Handle(cfg.CallbackPath, rp.CodeExchangeHandler(rp.UserinfoCallback(loginCallback), provider))

	http.HandleFunc("/logout", logout)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !validateSession(w, r, provider) {
			http.Redirect(w, r, "/nologin", http.StatusFound)
		} else {
			_, _ = w.Write([]byte("<html><h1>oh, wow!</h1><p><a href=\"/logout\">Logout</a></p></html>"))
		}
	})

	http.HandleFunc("/nologin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><a href=\"/login\">Login</a></html>"))
	})

	if err := http.ListenAndServe(cfg.AppBindAddress, nil); !errors.Is(err, http.ErrServerClosed) {
		pfxlog.Errorf("error: %v", err)
		os.Exit(1)
	}
}

func encryptRefreshToken(token string) (string, error) {
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       secretsKey,
		},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %v", err)
	}

	obj, err := enc.Encrypt([]byte(token))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt token: %v", err)
	}

	return obj.CompactSerialize()
}

func decryptRefreshToken(encrypted string) (string, error) {
	obj, err := jose.ParseEncrypted(encrypted, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return "", fmt.Errorf("failed to parse encrypted token: %v", err)
	}

	decrypted, err := obj.Decrypt(secretsKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt token: %v", err)
	}

	return string(decrypted), nil
}

func validateSession(w http.ResponseWriter, r *http.Request, provider rp.RelyingParty) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		pfxlog.Errorf("unable to get '%v' cookie: %v", cookieName, err)
		return false
	}

	tkn, err := jwt.ParseWithClaims(cookie.Value, &oidcSessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(cfg.SigningKey), nil
	})
	if err != nil {
		pfxlog.Errorf("unable to parse jwt: %v", err)
		return false
	}

	claims := tkn.Claims.(*oidcSessionClaims)
	pfxlog.Logger().With("email", claims.Email, "accessExpiry", claims.AccessExpiry, "refreshToken", claims.RefreshToken).Info("found claims")

	// check if access token is expired or expiring soon (within 5 minutes)
	if time.Now().Add(cfg.BeforeExpiry).After(claims.AccessExpiry) && claims.RefreshToken != "" {
		pfxlog.Infof("access token expiring soon; attempting refresh")

		decryptedRefreshToken, err := decryptRefreshToken(claims.RefreshToken)
		if err != nil {
			pfxlog.Errorf("failed to decrypt refresh token: %v", err)
			return false
		}
		pfxlog.Infof("refresh token: %v", decryptedRefreshToken)

		newTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](context.TODO(), provider, decryptedRefreshToken, "", "")
		if err != nil {
			pfxlog.Errorf("failed to refresh access token: %v", err)
			return false
		}

		refreshToken := claims.RefreshToken
		if newTokens.RefreshToken != "" {
			encryptedRefreshToken, err := encryptRefreshToken(newTokens.RefreshToken)
			if err != nil {
				pfxlog.Errorf("failed to encrypt new refresh token: %v", err)
				return false
			}
			refreshToken = encryptedRefreshToken
		}

		newAccessExpiry := time.Now().Add(cfg.RefreshEvery)
		newClaims := oidcSessionClaims{
			Email:        claims.Email,
			RefreshToken: refreshToken,
			AccessExpiry: newAccessExpiry,
		}

		newJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
		signedJwt, err := newJwt.SignedString([]byte(cfg.SigningKey))
		if err != nil {
			pfxlog.Errorf("failed to sign refreshed jwt token: %v", err)
			return false
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    signedJwt,
			MaxAge:   int(cfg.CookieExpires.Seconds()),
			Domain:   cfg.CookieDomain,
			Path:     "/",
			Expires:  time.Now().Add(cfg.CookieExpires),
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		pfxlog.Infof("access token refreshed successfully")

	} else if time.Now().After(claims.AccessExpiry) {
		pfxlog.Warnf("session expired!")
		return false
	}

	return true
}

func loginCallback(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
	accessExpiry := time.Now().Add(cfg.RefreshEvery)

	var refreshToken string
	if tokens.RefreshToken != "" {
		encryptedToken, err := encryptRefreshToken(tokens.RefreshToken)
		if err != nil {
			pfxlog.Errorf("failed to encrypt refresh token: %v", err)
			return
		}
		refreshToken = encryptedToken
	}

	newJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, oidcSessionClaims{
		Email:        info.Email,
		RefreshToken: refreshToken,
		AccessExpiry: accessExpiry,
	})
	signedJwt, err := newJwt.SignedString([]byte(cfg.SigningKey))
	if err != nil {
		pfxlog.Errorf("failed to sign jwt token: %v", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    signedJwt,
		MaxAge:   int(cfg.CookieExpires.Seconds()),
		Domain:   cfg.CookieDomain,
		Path:     "/",
		Expires:  time.Now().Add(cfg.CookieExpires),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func logout(w http.ResponseWriter, r *http.Request) {
	var refreshToken string
	if cookie, err := r.Cookie(cookieName); err == nil {
		if tkn, err := jwt.ParseWithClaims(cookie.Value, &oidcSessionClaims{}, func(t *jwt.Token) (interface{}, error) {
			return []byte(cfg.SigningKey), nil
		}); err == nil {
			if claims, ok := tkn.Claims.(*oidcSessionClaims); ok {
				if claims.RefreshToken != "" {
					decryptedToken, err := decryptRefreshToken(claims.RefreshToken)
					if err != nil {
						pfxlog.Errorf("failed to decrypt refresh token during logout: %v", err)
					} else {
						refreshToken = decryptedToken
					}
				}
			}
		}
	}

	// clear local session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		MaxAge:   -1,
		Domain:   cfg.CookieDomain,
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// revoke refresh token if available
	if refreshToken != "" {
		if err := rp.RevokeToken(context.TODO(), provider, refreshToken, "refresh_token"); err != nil {
			pfxlog.Errorf("failed to revoke refresh token: %v", err)
		} else {
			pfxlog.Infof("refresh token revoked successfully")
		}
	}

	if endSessionUrl, err := rp.EndSession(context.TODO(), provider, refreshToken, fmt.Sprintf("%v/nologin", cfg.AppUrl), ""); err == nil {
		pfxlog.Infof("redirecting to end session url: %v", endSessionUrl)
		http.Redirect(w, r, endSessionUrl.String(), http.StatusFound)
	} else {
		pfxlog.Warnf("no end session url (%v); redirecting", err)
		http.Redirect(w, r, "/nologin", http.StatusFound)
	}
}

type oidcSessionClaims struct {
	Email        string    `json:"email"`
	RefreshToken string    `json:"refresh_token"`
	AccessExpiry time.Time `json:"access_expiry"`
	jwt.RegisteredClaims
}
