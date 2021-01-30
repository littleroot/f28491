package main

import (
	"context"
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/securecookie"
	"github.com/littleroot/go-pass"
)

// TODO: set up VM and copy gpg key and create SSH key pairs

//go:embed templates
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

var (
	templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))
)

func printUsage() {
	fmt.Fprintf(os.Stderr, "usage: f28491 <conf.toml>\n")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	err := run(context.Background())
	if err != nil {
		log.Fatalf("%s", err)
	}
}

type server struct {
	cookie             *securecookie.SecureCookie
	googleClientID     string
	googleClientSecret string
	passwordStoreDir   string
	sshPrivateKeyFile  string

	mu sync.Mutex
}

type Conf struct {
	HttpServiceAddress string
	PasswordStoreDir   string
	AllowedEmails      []string
	GoogleClientID     string
	GoogleClientSecret string
	CookieHashKey      string
	CookieBlockKey     string
	SSHPrivateKeyFile  string
	PasswordsGit       string
}

func run(ctx context.Context) error {
	flag.Parse()

	if flag.NArg() != 1 {
		printUsage()
		os.Exit(2)
	}

	f, err := os.Open(flag.Arg(0))
	if err != nil {
		return fmt.Errorf("%s", err)
	}

	var c Conf
	if _, err := toml.DecodeReader(f, &c); err != nil {
		return fmt.Errorf("decode conf: %s", err)
	}

	if err := ensurePasswordStoreDir(ctx, c.PasswordsGit, c.PasswordStoreDir); err != nil {
		return fmt.Errorf("password store dir: %s", err)
	}

	cookie, err := constructCookie(c.CookieHashKey, c.CookieBlockKey)
	if err != nil {
		return fmt.Errorf("construct cookie: %s", err)
	}

	sshPriv, err := filepath.Abs(c.SSHPrivateKeyFile)
	if err != nil {
		return fmt.Errorf("construct absolute path to ssh private key file: %s", err)
	}

	allowedEmails := make(map[string]struct{})
	for _, e := range c.AllowedEmails {
		allowedEmails[e] = struct{}{}
	}

	s := &server{
		cookie:             cookie,
		googleClientID:     c.GoogleClientID,
		googleClientSecret: c.GoogleClientSecret,
		passwordStoreDir:   c.PasswordStoreDir,
		sshPrivateKeyFile:  sshPriv,
	}

	http.Handle("/api/list", allowedEmailsOnly(http.HandlerFunc(s.apiListHandler), allowedEmails))
	http.Handle("/api/show", allowedEmailsOnly(http.HandlerFunc(s.apiShowHandler), allowedEmails))
	http.Handle("/api/git", allowedEmailsOnly(http.HandlerFunc(s.apiGitHandler), allowedEmails))

	http.HandleFunc("/", s.indexHandler)

	// http.HandleFunc("/login", loginHandler)
	// http.HandleFunc("/auth/google", authGoogleHandler)
	// http.HandleFunc("/logout", logoutHandler)

	http.Handle("/static/", http.FileServer(http.FS(staticFS)))

	log.Printf("listening on %s", c.HttpServiceAddress)
	return http.ListenAndServe(c.HttpServiceAddress, nil)
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
	return cookie, nil
}

func ensurePasswordStoreDir(ctx context.Context, passwordsGit, path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		log.Printf("password store directory does not exist; running git clone ...")
		return clonePasswordStoreDir(ctx, passwordsGit, path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", path)
	}
	log.Printf("password store directory exists; skipping git clone")
	return nil
}

func clonePasswordStoreDir(ctx context.Context, passwordsGit, path string) error {
	output, err := exec.CommandContext(ctx, "git", "clone", passwordsGit, path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone passwords repository: %s: %s", err, output)
	}
	return nil
}

func (s *server) passOptions() *pass.Options {
	return &pass.Options{
		StoreDir: s.passwordStoreDir,
	}
}

func allowedEmailsOnly(h http.Handler, allowed map[string]struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: validate cookie and check email
		h.ServeHTTP(w, r)
	})
}
