# uaaclient

UAA client provides receiving a token on behalf of the user.

Example middleware handle for authorizing a client in an application

```golang
// simple session list
var sessionList  = make(map[string]string)

// create new UAA client
UAAClient, _ = uaaclient.New(uaaclient.Config{
    ClientID:    "myapp",
    Host:        "localhost",
    Scheme:      "http",
    Secret:      "mysecret",
    RedirectURL: "/myapp/",
    UAAEndpoint: "/oauth",
})

func authorization(pass http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// search code in request
		if code, ok := uaaclient.GetCode(r); ok {
			// the code is exchanged for a token from the UAA server
			token, err := UAAClient.CodeToken(code)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// creating a new session and writing it to cookies
			sessionID := UAAClient.SetSessionCookie(w, r)

			sessionList[sessionID] = token

			pass(w, r)
			return

			// cookie session search
		} else if sessionID, err := uaaclient.GetSessionID(r); err == nil {

			if _, ok := sessionList[sessionID]; ok {
				pass(w, r)
				return
			}
		}

		// redirect of unauthorized users to the login page
		UAAClient.AuthRedirect(w, r, "")
	}
}

func handleApp(w http.ResponseWriter, r *http.Request) {
    // handle action
}

http.HandleFunc("/myapp/", authorization(handleApp))
```
