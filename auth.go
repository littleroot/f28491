package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	CookieNameUserInfo = "passweb_userinfo"
	CookieNameState    = "passweb_state"

	CookieAge = 15 * 24 * time.Hour
)

func logOutHTML(message string) string {
	return fmt.Sprintf(`<p>%s</p><p><a href="/logout">Log out</a></p>`, message)
}

func writeErrorHTML(w http.ResponseWriter, html string, code int) {
	w.WriteHeader(code)
	io.WriteString(w, html)
}

func constructCookie(hash, block string) (*securecookie.SecureCookie, error) {
	h, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(block)
	if err != nil {
		return nil, err
	}
	cookie := securecookie.New(h, b)
	cookie.SetSerializer(securecookie.JSONEncoder{})
	cookie.MaxAge(int(CookieAge / time.Second))
	return cookie, nil
}

type GoogleUserInfo struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func isSecureCookieExpired(err error) bool {
	// Hacky way to check for cookie expired, since the securecookie package
	// does not appear to provide a better way.
	return err != nil && strings.Contains(err.Error(), "expired timestamp")
}

var ErrNoUser = errors.New("no current user")

// currentUser returns the currently logged in user's info. If there is no
// user logged in, the error is ErrNoUser.
func (s *server) currentUser(r *http.Request) (GoogleUserInfo, error) {
	c, err := r.Cookie(CookieNameUserInfo)
	if err == http.ErrNoCookie {
		return GoogleUserInfo{}, ErrNoUser
	}
	if err != nil {
		return GoogleUserInfo{}, fmt.Errorf("get cookie: %s", err)
	}

	var info GoogleUserInfo
	err = s.cookie.Decode(CookieNameUserInfo, c.Value, &info)
	if isSecureCookieExpired(err) {
		return GoogleUserInfo{}, ErrNoUser
	}
	if err != nil {
		return GoogleUserInfo{}, fmt.Errorf("decode user info cookie: %s", err)
	}
	return info, nil
}

func oauthStateParam() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("read rand: %s", err))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func googleOAuthConfig(clientID, clientSecret, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"profile", "email", "openid"},
		RedirectURL:  redirectURL,
		Endpoint:     google.Endpoint,
	}
}

func (s *server) loginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if _, err := s.currentUser(r); err == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		config := googleOAuthConfig(s.googleClientID, s.googleClientSecret, s.baseURL+"/auth")
		state := oauthStateParam()

		enc, err := s.cookie.Encode(CookieNameState, state)
		if err != nil {
			log.Printf("encode state cookie: %s", err)
			writeErrorHTML(w, logOutHTML("failed to encode cookie"), http.StatusInternalServerError)
			return
		}

		switch s.env {
		case Dev:
			http.SetCookie(w, &http.Cookie{
				Name:     CookieNameState,
				Value:    enc,
				Expires:  time.Now().Add(CookieAge),
				Secure:   false,
				HttpOnly: true,
			})
		case Production:
			http.SetCookie(w, &http.Cookie{
				Name:     CookieNameState,
				Value:    enc,
				Expires:  time.Now().Add(CookieAge),
				Secure:   true,
				HttpOnly: true,
			})
		}

		// Redirect user to consent page to ask for permission
		// for the scopes specified above.
		url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
		http.Redirect(w, r, url, http.StatusFound)
	})
}

func (s *server) authHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		config := googleOAuthConfig(s.googleClientID, s.googleClientSecret, s.baseURL+"/auth")

		code := r.URL.Query().Get("code")
		tok, err := config.Exchange(ctx, code)
		if err != nil {
			log.Printf("exchange code: %s", err)
			writeErrorHTML(w, logOutHTML("bad 'code' value"), http.StatusInternalServerError)
			return
		}

		if err := verifyStateParam(s.cookie, r); err != nil {
			log.Printf("verify state param: %s", err)
			writeErrorHTML(w, logOutHTML("try again"), http.StatusInternalServerError)
			return
		}

		// set up deletion of state cookie
		switch s.env {
		case Dev:
			http.SetCookie(w, &http.Cookie{
				Name:     CookieNameState,
				MaxAge:   -1, // delete cookie
				Secure:   false,
				HttpOnly: true,
			})
		case Production:
			http.SetCookie(w, &http.Cookie{
				Name:     CookieNameState,
				MaxAge:   -1, // delete cookie
				Secure:   true,
				HttpOnly: true,
			})
		}

		// fetch user info from Google
		client := config.Client(ctx, tok)

		req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
		if err != nil {
			log.Printf("build request: %s", err)
			writeErrorHTML(w, logOutHTML("try again"), http.StatusInternalServerError)
			return
		}
		req = req.WithContext(ctx)

		rsp, err := client.Do(req)
		if err != nil {
			log.Printf("do request: %s", err)
			writeErrorHTML(w, logOutHTML("try again"), http.StatusInternalServerError)
			return
		}
		defer drainAndClose(rsp.Body)

		if rsp.StatusCode != 200 {
			log.Printf("bad status code from google: %d", rsp.StatusCode)
			writeErrorHTML(w, logOutHTML("try again"), http.StatusInternalServerError)
			return
		}

		var info GoogleUserInfo

		if err := json.NewDecoder(rsp.Body).Decode(&info); err != nil {
			log.Printf("json-decode google response: %s", err)
			writeErrorHTML(w, logOutHTML("try again"), http.StatusInternalServerError)
			return
		}

		if !info.EmailVerified {
			log.Printf("unverified email %s", info.Email)
			writeErrorHTML(w, logOutHTML("unverified"), http.StatusForbidden)
			return
		}

		_, ok := s.allowedEmails[info.Email]
		if !ok {
			log.Printf("disallowed email %s", info.Email)
			writeErrorHTML(w, logOutHTML("disallowed"), http.StatusForbidden)
			return
		}

		// set up writing of user info cookie
		encoded, err := s.cookie.Encode(CookieNameUserInfo, info)
		if err != nil {
			log.Printf("failed to encode cookie: %s", err)
			writeErrorHTML(w, "internal server error", http.StatusInternalServerError)
			return
		}

		switch s.env {
		case Dev:
			http.SetCookie(w, &http.Cookie{
				Name:     CookieNameUserInfo,
				Value:    encoded,
				Expires:  time.Now().Add(CookieAge),
				Secure:   false,
				HttpOnly: true,
			})
		case Production:
			http.SetCookie(w, &http.Cookie{
				Name:     CookieNameUserInfo,
				Value:    encoded,
				Expires:  time.Now().Add(CookieAge),
				Secure:   true,
				HttpOnly: true,
			})
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func (s *server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	switch s.env {
	case Dev:
		http.SetCookie(w, &http.Cookie{
			Name:     CookieNameState,
			MaxAge:   -1, // delete cookie
			Secure:   false,
			HttpOnly: true,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     CookieNameUserInfo,
			MaxAge:   -1, // delete cookie
			Secure:   false,
			HttpOnly: true,
		})
	case Production:
		http.SetCookie(w, &http.Cookie{
			Name:     CookieNameState,
			MaxAge:   -1, // delete cookie
			Secure:   true,
			HttpOnly: true,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     CookieNameUserInfo,
			MaxAge:   -1, // delete cookie
			Secure:   true,
			HttpOnly: true,
		})
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func verifyStateParam(cookie *securecookie.SecureCookie, r *http.Request) error {
	incoming := r.URL.Query().Get("state")

	var expect string

	c, err := r.Cookie(CookieNameState)
	if err != nil {
		return fmt.Errorf("get cookie: %s", err)
	}

	err = cookie.Decode(CookieNameState, c.Value, &expect)
	if isSecureCookieExpired(err) {
		return fmt.Errorf("state cookie expired: %s", err)
	}
	if err != nil {
		return fmt.Errorf("decode state cookie: %s", err)
	}

	if expect != incoming {
		return fmt.Errorf("state value mismatch: %s != %s", expect, incoming)
	}
	return nil
}
