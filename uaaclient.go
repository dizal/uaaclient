package uaaclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/net/context/ctxhttp"
	"golang.org/x/oauth2"
)

// Config for UaaClient
type Config struct {
	// ClientID is the application's ID.
	ClientID string
	// ClientSecret is the application's secret.
	Secret string
	// http or https
	Scheme string
	// Host is the UAA host
	Host string
	// UAAEndpoint is the UAA endpoint that is obtained from hitting
	UAAEndpoint string
	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	Scopes []string

	Context context.Context
}

// UaaClient ...
type UaaClient struct {
	ctx         context.Context
	oauthConfig *oauth2.Config
	config      *Config
	uaauri, uri string
}

// DefaultConfig ...
func DefaultConfig() *Config {
	return &Config{
		ClientID:    "oauthClient",
		Scheme:      "http",
		Host:        "localhost",
		Secret:      "secret",
		UAAEndpoint: "/oauth",
		RedirectURL: "/",
		Context:     context.Background(),
	}
}

// New ...
func New(cfg Config) (*UaaClient, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("ClientID = nil")
	}

	if cfg.Secret == "" {
		cfg.Secret = simpleUUID()
	}

	if cfg.Scheme == "" {
		cfg.Scheme = "http"
	}

	if !(cfg.Scheme == "https" || cfg.Scheme == "http") {
		return nil, fmt.Errorf("Unknown protocol scheme: [%s]", cfg.Scheme)
	}

	if cfg.Context == nil {
		cfg.Context = context.Background()
	}

	uri := fmt.Sprintf("%s://%s", cfg.Scheme, cfg.Host)
	uaauri := uri + cfg.UAAEndpoint

	oauthConfig := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.Secret,
		Scopes:       cfg.Scopes,
		RedirectURL:  cfg.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:   fmt.Sprintf("%s/authorize", cfg.UAAEndpoint),
			TokenURL:  fmt.Sprintf("%s/token", uaauri),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	uaaClient := &UaaClient{
		ctx:         cfg.Context,
		oauthConfig: &oauthConfig,
		config:      &cfg,
		uaauri:      uaauri,
		uri:         uri,
	}

	return uaaClient, nil
}

// AuthRedirect ...
func (u *UaaClient) AuthRedirect(w http.ResponseWriter, r *http.Request, state string, opts ...oauth2.AuthCodeOption) {
	http.Redirect(w, r, u.oauthConfig.AuthCodeURL(state, opts...), http.StatusFound)
}

// PasswordCredentialsToken ...
func (u *UaaClient) PasswordCredentialsToken(username, password string) (*Token, error) {
	token, err := u.oauthConfig.PasswordCredentialsToken(u.ctx, username, password)
	if err != nil {
		return nil, err
	}

	return oauth2tokenToToken(token), nil
}

// CodeToken ...
func (u *UaaClient) CodeToken(code string, opts ...oauth2.AuthCodeOption) (*Token, error) {
	token, err := u.oauthConfig.Exchange(u.ctx, code, opts...)
	if err != nil {
		return nil, err
	}

	return oauth2tokenToToken(token), nil
}

// ValidToken ...
func (u *UaaClient) ValidToken(t *Token) error {
	var path strings.Builder
	path.Grow(len(u.uri) + len("/check_token"))
	path.WriteString(u.uri)
	path.WriteString("/check_token")

	req, err := http.NewRequest("POST", path.String(), strings.NewReader("token="+t.AccessToken))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	u.SetBaseAuth(req)

	res, status, err := u.do(req)
	if err != nil {
		return err
	}

	switch status {
	case http.StatusOK:
		return nil
	case http.StatusBadRequest:
		{
			type warnResp struct {
				Desc string `json:"error_description"`
			}

			if res != nil {
				var r warnResp
				if err = json.Unmarshal(res, &r); err == nil {
					return fmt.Errorf("Invalid token: %s", r.Desc)
				}
			}
			return fmt.Errorf("Could not verify token")
		}
	case http.StatusUnauthorized:
		return fmt.Errorf("Failed to decode basic authentication token")
	default:
		{
			var r = ""
			if res != nil {
				r = string(r)
			}
			return fmt.Errorf("Error with validation token. Status %d. Resp: %s", status, r)
		}
	}
}

// SetBaseAuth ...
func (u *UaaClient) SetBaseAuth(r *http.Request) {
	base := base64.StdEncoding.EncodeToString([]byte(u.oauthConfig.ClientID + ":" + u.oauthConfig.ClientSecret))
	r.Header.Add("Authorization", "Basic "+base)
}

// GetCode searches for code in request query
func GetCode(r *http.Request) (string, bool) {
	v, ok := r.URL.Query()["code"]
	if ok && len(v) > 0 {
		return v[0], true
	}

	return "", false
}

func (u *UaaClient) do(req *http.Request) ([]byte, int, error) {
	r, err := ctxhttp.Do(u.ctx, oauth2.NewClient(u.ctx, nil), req)
	if err != nil {
		return nil, 0, err
	}

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()

	if err != nil {
		return nil, 0, fmt.Errorf("uaaclient: cannot read body: %v", err)
	}
	return body, r.StatusCode, nil
}

func simpleUUID() string {
	var uuid string

	b := [16]byte{}
	if _, err := rand.Read(b[:]); err == nil {
		uuid = fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	}

	return uuid
}
