package main

import (
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gorilla/securecookie"
	"github.com/littleroot/go-pass"
)

//go:embed templates
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

var (
	templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))
)

const (
	passwordsGit = "git@github.com:nishanths/passwords.git"
)

var (
	fHttp             = flag.String("http", ":52849", "http service address")
	fPasswordStoreDir = flag.String("storedir", "password-store", "location of password-store directory")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	err := run(context.Background())
	if err != nil {
		log.Fatalf("%s", err)
	}
}

type server struct {
	allowedEmails      []string
	cookie             *securecookie.SecureCookie
	googleClientID     string
	googleClientSecret string
	passwordStoreDir   string

	mu sync.Mutex
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

func checkEnv() bool {
	return os.Getenv("COOKIE_HASH_KEY") != "" &&
		os.Getenv("COOKIE_BLOCK_KEY") != "" &&
		os.Getenv("ALLOWED_EMAILS") != "" &&
		os.Getenv("GOOGLE_CLIENT_ID") != "" &&
		os.Getenv("GOOGLE_CLIENT_SECRET") != ""
}

func ensurePasswordStoreDir(ctx context.Context, path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		log.Printf("password store directory does not exist; running git clone")
		return clonePasswordStoreDir(ctx, path)
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

func clonePasswordStoreDir(ctx context.Context, path string) error {
	output, err := exec.CommandContext(ctx, "git", "clone", passwordsGit, path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone passwords repository: %s: %s", err, output)
	}
	return nil
}

func run(ctx context.Context) error {
	flag.Parse()

	if !checkEnv() {
		return errors.New("missing one or more required env vars")
	}

	if err := ensurePasswordStoreDir(ctx, *fPasswordStoreDir); err != nil {
		return fmt.Errorf("password store dir: %s", err)
	}

	cookie, err := constructCookie(os.Getenv("COOKIE_HASH_KEY"), os.Getenv("COOKIE_BLOCK_KEY"))
	if err != nil {
		return fmt.Errorf("construct cookie: %s", err)
	}

	allowedEmails := strings.Split(os.Getenv("ALLOWED_EMAILS"), ",")

	s := &server{
		allowedEmails:      allowedEmails,
		cookie:             cookie,
		googleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		googleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		passwordStoreDir:   *fPasswordStoreDir,
	}

	// TODO: allowed emails only middleware
	http.HandleFunc("/api/list", s.apiListHandler)
	http.HandleFunc("/api/show", s.apiShowHandler)
	// http.HandleFunc("/api/insert", insertHandler)
	// http.HandleFunc("/api/git", gitHandler)
	// http.HandleFunc("/api/mv", mvHandler)
	// http.HandleFunc("/api/cp", cpHandler)
	// http.HandleFunc("/api/rm", rmHandler)

	http.HandleFunc("/", s.indexHandler)

	// http.HandleFunc("/login", loginHandler)
	// http.HandleFunc("/auth/google", authGoogleHandler)
	// http.HandleFunc("/logout", logoutHandler)

	http.Handle("/static/", http.FileServer(http.FS(staticFS)))

	log.Printf("listening on %s", *fHttp)
	return http.ListenAndServe(*fHttp, nil)
}

func (s *server) passOptions() *pass.Options {
	return &pass.Options{
		StoreDir: s.passwordStoreDir,
	}
}
