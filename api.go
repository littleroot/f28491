package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"

	"github.com/littleroot/f28491/api"
	"github.com/littleroot/go-pass"
)

func (s *server) apiGitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	var req api.GitRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !isAllowedGitCommand(req.Args) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	output, err := execGit(ctx, s.sshPrivateKeyFile, s.passwordStoreDir, req.Args)
	if err != nil {
		log.Printf("exec git: %s: %s", err, output)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
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

func isAllowedGitCommand(args []string) bool {
	return len(args) == 1 && args[0] == "pull"
}

func (s *server) apiListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	s.mu.Lock()
	defer s.mu.Unlock()

	items, err := pass.List(ctx, "", s.passOptions())
	if err != nil {
		log.Printf("%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(api.ListResponse(items))
	if err != nil {
		log.Printf("write json: %s", err)
	}
}

func (s *server) apiShowHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	name := r.FormValue("name")
	gpgPassphrase := r.FormValue("gpg-passphrase")

	if name == "" || gpgPassphrase == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Reloads gpg-agent which forces gpg to forget passphrase, so that the
	// passphrase is now required.
	// See https://superuser.com/a/887987.
	if err := reloadGpgAgent(); err != nil {
		log.Printf("reload gpg-agent: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	content, err := pass.Show(ctx, name, gpgPassphrase, s.passOptions())
	if err != nil {
		log.Printf("%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(api.ShowResponse(content))
	if err != nil {
		log.Printf("write json: %s", err)
	}
}

func reloadGpgAgent() error {
	output, err := exec.Command("gpgconf", "--reload", "gpg-agent").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, output)
	}
	return nil
}
