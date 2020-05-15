package uaaclient

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Token ...
type Token struct {
	oauth2.Token
	Payload Payload
}

// Payload ...
type Payload struct {
	// JWT ID. unique identifier for this token
	Jti string `json:"jti"`
	// JWT Time the token was issued (epoch)
	IatRaw int64 `json:"iat"`
	Iat    time.Time
	// JWT Time the token expires (epoch)
	ExpRaw int64 `json:"exp"`
	Exp    time.Time
	// JWT Issuer (who created and signed this token)
	Iss string `json:"iss"`
	// UAA Used in multi-tenant environments to identity the tenant
	Zid string `json:"zid"`
	// UAA Identity provider that authenticated the end-user
	Origin string `json:"origin"`
	// UAA Canonical username of the end-user
	UserName string `json:"user_name"`
	// OIDC Email address of the end-user
	Email string `json:"email"`
	// OIDC Subject (who the token refers to)
	Sub string `json:"sub"`
	// OAuth List of scopes (group memberships) this access token has
	Scope []string `json:"scope"`
	//
	Authorities []string `json:"authorities"`
	// OAuth Client ID that requested the token
	ClientID string `json:"client_id"`
	// OAuth Type of authorization grant
	GrantType string `json:"grant_type"`
}

// UnsafeParsePayload deserializes JWT and saves the result in Payload.
// For signed JWTs, the claims are not verified. This function won't work for encrypted JWTs.
func (t *Token) UnsafeParsePayload() error {
	var payload Payload

	if token, err := jwt.ParseSigned(t.AccessToken); err != nil {
		return fmt.Errorf("Cannot parse token: %v", err)
	} else if err := token.UnsafeClaimsWithoutVerification(&payload); err != nil {
		return fmt.Errorf("Cannot parse token payload: %v", err)
	}

	payload.Iat = time.Unix(payload.IatRaw, 0)
	payload.Exp = time.Unix(payload.ExpRaw, 0)

	t.Payload = payload

	return nil
}

// TokenFromHeader searches for Token in the request header.
// Tries to deserialize JWT to get an expiration date.
func TokenFromHeader(r *http.Request) (*Token, bool, error) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		return nil, false, nil
	}
	if strings.HasPrefix(tokenStr, "Bearer") {
		// Bearer <token>. Delete first 7 symbols
		tokenStr = tokenStr[7:]
	} else {
		return nil, true, fmt.Errorf("Token type is not a Bearer")
	}

	token := Token{
		Token: oauth2.Token{
			AccessToken: tokenStr,
			TokenType:   "bearer",
		},
	}

	if err := token.UnsafeParsePayload(); err != nil {
		return &token, true, err
	}

	token.Expiry = token.Payload.Exp

	return &token, true, nil
}

func oauth2tokenToToken(token *oauth2.Token) *Token {
	return &Token{Token: *token}
}
