package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/michaelquigley/cf"
	frontend_oidc "github.com/michaelquigley/frontend-oidc"
	"github.com/michaelquigley/pfxlog"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func init() {
	pfxlog.GlobalInit(slog.LevelInfo, pfxlog.DefaultOptions().SetTrimPrefix("github.com/michaelquigley/frontend-oidc/"))
}

func main() {
	cfg, err := frontend_oidc.LoadConfig(os.Args[1])
	if err != nil {
		panic(err)
	}
	if cfg.OIDC == nil {
		pfxlog.Error("oidc config is empty")
		os.Exit(1)
	}
	pfxlog.Info(cf.Dump(cfg, cf.DefaultOptions()))

	secretsKey, err := frontend_oidc.DeriveKey(cfg.SecretsKey, 32)
	if err != nil {
		pfxlog.Error(err)
		os.Exit(1)
	}

	redirectUrl := fmt.Sprintf("%v%v", cfg.AppUrl, cfg.CallbackPath)
	cookieHandler := httphelper.NewCookieHandler(secretsKey, secretsKey, httphelper.WithUnsecure())
	providerOptions := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithSigningAlgsFromDiscovery(),
	}
	if cfg.Pkce {
		providerOptions = append(providerOptions, rp.WithPKCE(cookieHandler))
	}
	provider, err := rp.NewRelyingPartyOIDC(context.TODO(), cfg.OIDC.Issuer, cfg.ClientId, cfg.ClientSecret, redirectUrl, cfg.Scopes, providerOptions...)
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

	codeExchangeHandler := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
		pfxlog.Logger().With("accessToken", tokens.AccessToken, "refreshToken", tokens.RefreshToken, "idToken", tokens.IDToken).Warn("received tokens")

		data, err := json.Marshal(info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		pfxlog.Info(string(data))

		w.Header().Set("content-type", "application/json")
		w.Write(data)
	}

	http.Handle(cfg.CallbackPath, rp.CodeExchangeHandler(rp.UserinfoCallback(codeExchangeHandler), provider))

	err = http.ListenAndServe(cfg.AppBindAddress, http.DefaultServeMux)
	if err != nil {
		panic(err)
	}
}
