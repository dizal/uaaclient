package uaaclient

import "encoding/json"

// Client ...
type Client struct {
	// Client identifier, unique within identity zone.
	// Required
	ClientID string `json:"client_id"`

	// List of grant types that can be used to obtain a token with this client.
	// Can include authorization_code, password, implicit, and/or client_credntials.
	// Optional
	AuthorizedGrantTypes []string `json:"authorized_grant_types,omitempty"`

	// Allowed URI pattern for redirect during authorization.
	// Wildcard patterns can be specified using the Ant-style pattern.
	// Null/Empty value is forbidden.
	// Optional
	RedirectURI []string `json:"redirect_uri,omitempty"`

	// Scopes allowed for the client.
	// Optional (defaults to "uaa.none")
	Scope []string `json:"scope,omitempty"`

	// Resources the client is allowed access to
	// Optional (defaults to [])
	ResourceIds []string `json:"resource_ids,omitempty"`

	// Scopes which the client is able to grant when creating a client.
	// Optional (defaults to "uaa.none")
	Authorities []string `json:"authorities,omitempty"`

	// Scopes that do not require user approval.
	// Optional (defaults to [])
	Autoapprove interface{} `json:"autoapprove,omitempty"`

	// Time in seconds to access token expiration after it is issued
	// Optional
	AccessTokenValidity uint32 `json:"access_token_validity,omitempty"`

	// time in seconds to refresh token expiration after it is issued
	// Optional
	RefreshTokenValidity uint32 `json:"refresh_token_validity,omitempty"`

	// 	A list of origin keys (alias) for identity providers the client
	// is limited to. Null implies any identity provider is allowed.
	// Optional
	Allowedproviders []string `json:"allowedproviders,omitempty"`

	// A human readable name for the client
	// Optional
	Name string `json:"name,omitempty"`

	// A random string used to generate the client's revokation key.
	// Change this value to revoke all active tokens for the client.
	// Optional
	TokenSalt string `json:"token_salt,omitempty"`

	// What scope the bearer token had when client was created
	// Optional
	CreatedWith string `json:"createdwith,omitempty"`

	// A list of group names. If a user doesn't belong to all the required
	// groups, the user will not be authenticated and no tokens will be issued
	// to this client for that user. If this field is not set, authentication
	// and token issuance will proceed normally.
	// Optional
	RequiredUserGroups []string `json:"required_user_groups,omitempty"`

	// A secret string used for authenticating as this client. To support
	// secret rotation this can be space delimited string of two secrets.
	// Required if the client allows authorization_code or client_credentials
	// grant type
	ClientSecret string `json:"client_secret,omitempty"`

	extra map[string]interface{}
}

// MarshalJSON ...
func (c *Client) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(*c)
	if err != nil {
		return nil, err
	}

	var x map[string]interface{}
	if err = json.Unmarshal(b, &x); err != nil {
		return nil, err
	}

	for k, v := range c.extra {
		x[k] = v
	}
	return json.Marshal(x)
}

// UnmarshalJSON ...
func (c *Client) UnmarshalJSON(b []byte) error {
	type tempClient *Client

	if err := json.Unmarshal(b, (tempClient)(c)); err != nil {
		return err
	}
	var x map[string]interface{}
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}

	c.extra = make(map[string]interface{})

	for k, v := range x {
		switch k {
		case "client_id", "authorized_grant_types", "redirect_uri",
			"scope", "resource_ids", "authorities", "autoapprove",
			"access_token_validity", "refresh_token_validity",
			"allowedproviders", "name", "token_salt", "createdwith",
			"required_user_groups", "client_secret":
			continue
		default:
			c.extra[k] = v
		}
	}

	return nil
}

// SetExtra ...
func (c *Client) SetExtra(key string, value interface{}) {
	if c.extra == nil {
		c.extra = make(map[string]interface{})
	}
	c.extra[key] = value
}

// GetExtra ...
func (c *Client) GetExtra(key string) (interface{}, bool) {
	v, ok := c.extra[key]
	return v, ok
}
