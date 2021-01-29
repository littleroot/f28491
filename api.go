package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"

	"github.com/littleroot/go-pass"
)

type ListResponse []string

func (s *server) apiListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := r.Context()

	items, err := pass.List(ctx, "", s.passOptions())
	if err != nil {
		log.Printf("%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(items)
	if err != nil {
		log.Printf("write json: %s", err)
	}
}

type ShowResponse string

func (s *server) apiShowHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := r.Context()

	name := r.FormValue("name")
	gpgPassphrase := r.FormValue("gpg-passphrase")

	if name == "" || gpgPassphrase == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	content, err := pass.Show(ctx, name, gpgPassphrase, s.passOptions())
	if err != nil {
		log.Printf("%s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Reloads gpg-agent which forces gpg to forget passphrase, so that the
	// passphrase is required for the next request.
	// See https://superuser.com/a/887987.
	err = reloadGpgAgent()
	if err != nil {
		log.Printf("reload gpg-agent: %s")
	}

	err = json.NewEncoder(w).Encode(string(content))
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
