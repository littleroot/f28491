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

// Serves an individual item's password page.
func (s *server) passwordHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}

	info, err := s.currentUser(r)
	if err != nil {
		// code bug: error should be nil due to middleware
		panic(err)
	}

	if err := templates.ExecuteTemplate(w, "password.html", PasswordTemplateData{
		Email: info.Email,
		Name:  name,
	}); err != nil {
		log.Printf("execute template password.html: %s", err)
	}
}

// Update the pass Git repository to the latest changes, using a git fetch
// followed by a git reset --hard. Note that we prefer this strategy over a
// merge/rebase in order to handle the case in which someone may have force
// pushed changes that are not possible to integrate with a merge/rebase.
func (s *server) updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	s.mu.Lock()
	defer s.mu.Unlock()

	output, err := execGit(ctx, s.sshPrivateKeyFile, s.passwordStoreDir, []string{"fetch"})
	if err != nil {
		log.Printf("exec git: %s: %s", err, output)
		http.Error(w, "failed git fetch. try again.", http.StatusInternalServerError)
		return
	}

	output, err = execGit(ctx, s.sshPrivateKeyFile, s.passwordStoreDir, []string{"reset", "--hard", "origin/" + s.branch})
	if err != nil {
		log.Printf("exec git: %s: %s", err, output)
		http.Error(w, "failed git reset. try again.", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}
