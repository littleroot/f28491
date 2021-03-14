// Command passweb provides a web user interface for pass, the password
// manager.
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
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

//go:embed templates
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

var (
	templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))
)

func printUsage() {
	fmt.Fprintf(os.Stderr, "usage: passweb <conf.toml>\n")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	err := run(context.Background())
	if err != nil {
		log.Fatalf("%s", err)
	}
}

type server struct {
	allowedEmails      map[string]struct{}
	cookie             *securecookie.SecureCookie
	googleClientID     string
	googleClientSecret string
	passwordStoreDir   string
	sshPrivateKeyFile  string
	env                Environment
	baseURL            string
	branch             string

	mu sync.Mutex // for all command-line operations (git, pass, etc.)

}

type Environment string

const (
	Dev        Environment = "dev"
	Production Environment = "production"
)

type Conf struct {
	Env                   Environment
	BaseURL               string
	HTTPServiceAddress    string
	AllowedGoogleAccounts []string
	GitRepository         string
	GitBranch             string
	PasswordStoreDir      string
	SSHPrivateKeyFile     string
	GoogleClientID        string
	GoogleClientSecret    string
	CookieHashKey         string
	CookieBlockKey        string
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

	switch c.Env {
	case Dev, Production:
	default:
		return fmt.Errorf("invalid Env %s", c.Env)
	}

	if err := ensurePasswordStoreDir(ctx, c.SSHPrivateKeyFile, c.GitRepository, c.PasswordStoreDir, c.GitBranch); err != nil {
		return fmt.Errorf("password store dir: %s", err)
	}

	cookie, err := constructCookie(c.CookieHashKey, c.CookieBlockKey)
	if err != nil {
		return fmt.Errorf("construct cookie: %s", err)
	}

	allowedEmails := make(map[string]struct{})
	for _, e := range c.AllowedGoogleAccounts {
		allowedEmails[e] = struct{}{}
	}

	sshPriv, err := filepath.Abs(c.SSHPrivateKeyFile)
	if err != nil {
		return fmt.Errorf("construct abs path: %s", err)
	}

	s := &server{
		allowedEmails:      allowedEmails,
		cookie:             cookie,
		googleClientID:     c.GoogleClientID,
		googleClientSecret: c.GoogleClientSecret,
		passwordStoreDir:   c.PasswordStoreDir,
		sshPrivateKeyFile:  sshPriv,
		env:                c.Env,
		baseURL:            c.BaseURL,
		branch:             c.GitBranch,
	}

	http.Handle("/api/show", s.apiAuthMiddleware(http.HandlerFunc(s.apiShowHandler)))

	http.Handle("/", s.authMiddleware(http.HandlerFunc(s.indexHandler)))
	http.Handle("/update", s.authMiddleware(http.HandlerFunc(s.updateHandler)))
	http.Handle("/p", s.authMiddleware(http.HandlerFunc(s.passwordHandler)))

	http.Handle("/login", s.loginHandler())
	http.Handle("/auth", s.authHandler())
	http.HandleFunc("/logout", s.logoutHandler)

	http.Handle("/static/", http.FileServer(http.FS(staticFS)))

	log.Printf("listening on %s", c.HTTPServiceAddress)
	log.Printf("%s", warning)
	return http.ListenAndServe(c.HTTPServiceAddress, nil)
}

const warning = `
SECURITY WARNING

passweb serves content over HTTP, not HTTPS. If you plan to serve passweb's
content on the Internet, you should set up a HTTPS reverse proxy that
terminates TLS and forwards requests to passweb.
`

func ensurePasswordStoreDir(ctx context.Context, sshPrivateKeyFile, gitRepository, path, branch string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		log.Printf("password store directory does not exist; running git clone ...")
		return clonePasswordStoreDir(ctx, sshPrivateKeyFile, gitRepository, path, branch)
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

// clone the pass Git repository and checkout the right branch.
func clonePasswordStoreDir(ctx context.Context, sshPrivateKeyFile, gitRepository, path, branch string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", gitRepository, path)
	cmd.Env = []string{
		fmt.Sprintf(`GIT_SSH_COMMAND=ssh -i %s -o IdentitiesOnly=yes`, sshPrivateKeyFile),
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone passwords repository: %s: %s", err, output)
	}

	output, err = execGit(ctx, sshPrivateKeyFile, path, []string{"checkout", branch})
	if err != nil {
		return fmt.Errorf("git checkout: %s: %s", err, output)
	}
	return nil
}

func (s *server) passOptions() *pass.Options {
	return &pass.Options{
		StoreDir: s.passwordStoreDir,
	}
}

func (s *server) apiAuthMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, err := s.currentUser(r)
		if err == ErrNoUser {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !info.EmailVerified {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		_, ok := s.allowedEmails[info.Email]
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func (s *server) authMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, err := s.currentUser(r)
		if err == ErrNoUser {
			if err := templates.ExecuteTemplate(w, "login.html", nil); err != nil {
				log.Printf("execute template login.html: %s", err)
			}
			return
		}
		if err != nil {
			log.Printf("%s", err)
			http.Error(w, "try again", http.StatusInternalServerError)
			return
		}

		if !info.EmailVerified {
			http.Redirect(w, r, "/logout", http.StatusFound) // kinda hacky but it should do for now
			return
		}

		_, ok := s.allowedEmails[info.Email]
		if !ok {
			http.Redirect(w, r, "/logout", http.StatusFound) // kinda hacky but it should do for now
			return
		}

		h.ServeHTTP(w, r)
	})
}

func drainAndClose(r io.ReadCloser) {
	io.Copy(ioutil.Discard, r)
	r.Close()
}

func reloadGpgAgent() error {
	output, err := exec.Command("gpgconf", "--reload", "gpg-agent").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, output)
	}
	return nil
}

func execGit(ctx context.Context, privateKeyFile, dir string, args []string) ([]byte, error) {
	var allArgs []string
	allArgs = append(allArgs, "--git-dir", filepath.Join(dir, ".git"))
	allArgs = append(allArgs, "--work-tree", dir)
	allArgs = append(allArgs, args...)

	cmd := exec.CommandContext(ctx, "git", allArgs...)
	cmd.Env = []string{
		fmt.Sprintf(`GIT_SSH_COMMAND=ssh -i %s -o IdentitiesOnly=yes`, privateKeyFile),
	}
	return cmd.CombinedOutput()
}
