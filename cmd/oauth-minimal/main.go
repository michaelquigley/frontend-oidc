package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/michaelquigley/cf"
	frontend_oidc "github.com/michaelquigley/frontend-oidc"
	"github.com/michaelquigley/pfxlog"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	zhttp "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

func init() {
	pfxlog.GlobalInit(slog.LevelInfo, pfxlog.DefaultOptions().SetTrimPrefix("github.com/michaelquigley/frontend-oidc/"))
}

func main() {
	cfg, err := frontend_oidc.LoadConfig(os.Args[1])
	if err != nil {
		panic(err)
	}
	if cfg.Oauth == nil {
		pfxlog.Error("oauth config is empty")
		os.Exit(1)
	}
	pfxlog.Info(cf.Dump(cfg, cf.DefaultOptions()))

	secretsKey, err := frontend_oidc.DeriveKey(cfg.SecretsKey, 32)
	if err != nil {
		pfxlog.Error(err)
		os.Exit(1)
	}

	redirectUrl := fmt.Sprintf("%v%v", cfg.AppUrl, cfg.CallbackPath)
	providerCfg := &oauth2.Config{
		ClientID:     cfg.ClientId,
		ClientSecret: cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.Oauth.AuthUrl,
			TokenURL: cfg.Oauth.TokenUrl,
		},
		RedirectURL: redirectUrl,
		Scopes:      cfg.Scopes,
	}
	cookieHandler := zhttp.NewCookieHandler(secretsKey, secretsKey, zhttp.WithUnsecure())
	providerOptions := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithSigningAlgsFromDiscovery(),
	}
	if cfg.Pkce {
		providerOptions = append(providerOptions, rp.WithPKCE(cookieHandler))
	}
	provider, err := rp.NewRelyingPartyOAuth(providerCfg, providerOptions...)
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

	codeExchangeHandler := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		pfxlog.Logger().With("accessToken", tokens.AccessToken, "refreshToken", tokens.RefreshToken, "idToken", tokens.IDToken).Warn("received tokens")

		parsedUrl, err := url.Parse(cfg.Oauth.UserinfoUrl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req := &http.Request{
			Method: http.MethodGet,
			URL:    parsedUrl,
			Header: make(http.Header),
		}
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logrus.Errorf("error getting user info: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		response, err := io.ReadAll(resp.Body)
		if err != nil {
			logrus.Errorf("error reading response body: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		pfxlog.Info(string(response))

		w.Header().Set("content-type", "application/json")
		w.Write(response)
	}
	http.Handle(cfg.CallbackPath, rp.CodeExchangeHandler(codeExchangeHandler, provider))

	err = http.ListenAndServe(cfg.AppBindAddress, http.DefaultServeMux)
	if err != nil {
		panic(err)
	}
}
