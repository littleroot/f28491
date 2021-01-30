package main

import (
	"log"
	"net/http"
)

type IndexTemplateData struct {
	Email string
}

func (s *server) indexHandler(w http.ResponseWriter, r *http.Request) {
	info, err := s.currentUser(r)

	if err == ErrNoUser {
		if err := templates.ExecuteTemplate(w, "login.html", nil); err != nil {
			log.Printf("execute template login.html: %s", err)
		}
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

	if err := templates.ExecuteTemplate(w, "index.html", IndexTemplateData{
		Email: info.Email,
	}); err != nil {
		log.Printf("execute template index.html: %s", err)
	}
}
