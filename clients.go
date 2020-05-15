package uaaclient

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

const clientEndpoint = "/clients/"

// Clients ...
type Clients struct{ u *UaaClient }

// Clients ...
func (u *UaaClient) Clients() *Clients { return &Clients{u} }

// Create ...
func (c *Clients) Create(t *Token, client *Client) (bool, error) {
	b, err := client.MarshalJSON()
	if err != nil {
		return false, err
	}

	var path strings.Builder
	path.Grow(len(c.u.uaauri) + len(clientEndpoint))
	path.WriteString(c.u.uaauri)
	path.WriteString(clientEndpoint)

	req, err := http.NewRequest("POST", path.String(), bytes.NewReader(b))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")
	t.SetAuthHeader(req)

	resp, status, err := c.u.do(req)
	if err != nil {
		return false, err
	}

	switch status {
	case http.StatusCreated:
		return true, nil
	case http.StatusConflict:
		return true, fmt.Errorf("uaaclient: Client already exists: %s", client.ClientID)
	case http.StatusBadRequest:
		return false, fmt.Errorf("uaaclient: Invalid request: %s", string(resp))
	default:
		return false, fmt.Errorf("uaaclient: Cannot create client %s. Status %d. %v", client.ClientID, status, resp)
	}
}

// Delete ...
func (c *Clients) Delete(t *Token, clientID string) (int, error) {
	var path strings.Builder
	path.Grow(len(c.u.uaauri) + len(clientEndpoint))
	path.WriteString(c.u.uaauri)
	path.WriteString(clientEndpoint)

	req, err := http.NewRequest("DELETE", path.String(), nil)
	if err != nil {
		return -1, err
	}

	t.SetAuthHeader(req)

	_, status, err := c.u.do(req)
	if err != nil {
		return status, err
	}

	return status, nil
}

// Get ...
func (c *Clients) Get(t *Token, clientID string) (*Client, error) {
	var path strings.Builder
	path.Grow(len(c.u.uaauri) + len(clientEndpoint) + len(clientID))
	path.WriteString(c.u.uaauri)
	path.WriteString(clientEndpoint)
	path.WriteString(clientID)

	req, err := http.NewRequest("GET", path.String(), nil)
	if err != nil {
		return nil, err
	}

	t.SetAuthHeader(req)

	resp, status, err := c.u.do(req)
	if err != nil {
		return nil, err
	}

	switch status {
	case http.StatusNotFound:
		return nil, fmt.Errorf("uaaclient: Client %s not found", clientID)
	case http.StatusOK:
		{
			var client Client
			if err = client.UnmarshalJSON(resp); err != nil {
				return nil, err
			}

			return &client, nil
		}
	default:
		return nil, fmt.Errorf("uaaclient: Cannot fetch client %s. Status %d", clientID, status)
	}
}
