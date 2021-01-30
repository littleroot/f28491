package main

import (
	"context"
	"log"
	"net/http"

	"github.com/littleroot/go-pass"
)

type IndexTemplateData struct {
	Email  string
	Items  []string
	Commit string
}

func (s *server) indexHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	info, err := s.currentUser(r)
	if err != nil {
		// code bug: error should be nil due to middleware
		panic(err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.renderIndexLock(ctx, w, info.Email)
}

func (s *server) renderIndexLock(ctx context.Context, w http.ResponseWriter, email string) {
	items, err := pass.List(ctx, "", s.passOptions())
	if err != nil {
		log.Printf("%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	commit, err := execGit(ctx, s.sshPrivateKeyFile, s.passwordStoreDir, []string{"rev-parse", "HEAD"})
	if err != nil {
		log.Printf("%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := templates.ExecuteTemplate(w, "index.html", IndexTemplateData{
		Email:  email,
		Items:  items,
		Commit: string(commit[:7]),
	}); err != nil {
		log.Printf("execute template index.html: %s", err)
	}
}

type PasswordTemplateData struct {
	Email string
	Name  string
}

func (s *server) passwordHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
}

func (s *server) gitPullHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	s.mu.Lock()
	defer s.mu.Unlock()

	output, err := execGit(ctx, s.sshPrivateKeyFile, s.passwordStoreDir, []string{"pull"})
	if err != nil {
		log.Printf("exec git: %s: %s", err, output)
		http.Error(w, "failed git pull; try again", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}
