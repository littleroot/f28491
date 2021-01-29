package main

import (
	"log"
	"net/http"
)

func (s *server) indexHandler(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "sign_in.html", nil)
	if err != nil {
		log.Printf("execute sign_in.html template: %s", err)
	}
}
