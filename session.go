package uaaclient

import (
	"fmt"
	"net/http"
)

// Session ...
type Session struct {
	ID     string
	Cookie http.Cookie
}

// SetSessionCookie creates a new session and writes it in a cookie.
func (o *UaaClient) SetSessionCookie(w http.ResponseWriter, r *http.Request) string {
	id := fmt.Sprintf("%s.%s", simpleUUID(), o.config.ClientID)

	cookie := http.Cookie{
		Name:     "JSESSIONID",
		Value:    id,
		Path:     o.config.RedirectURL,
		Domain:   r.Host,
		HttpOnly: true,
	}

	http.SetCookie(w, &cookie)

	return id
}

// GetSessionID returns session ID from cookie
func GetSessionID(r *http.Request) (string, error) {
	sessionCookie, err := r.Cookie("JSESSIONID")
	if err != nil {
		return "", err
	}

	return sessionCookie.Value, nil
}
