package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/littleroot/go-pass"
)

type ShowResponse string

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

	if err := reloadGpgAgent(); err != nil {
		log.Printf("reload gpg-agent: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(ShowResponse(content))
	if err != nil {
		log.Printf("write json: %s", err)
	}
}
