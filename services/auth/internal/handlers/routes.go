package servicehttp

import (
	"net/http"

	"github.com/ncundstnd/go-mservices/services/auth/internal/repository"
)

type Handler struct {
	UserRepo *repository.UserRepository
}

func RegisterRoutes(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("POST /register", h.RegisterHandler)
	mux.HandleFunc("POST /login", h.LoginHandler)
	mux.HandleFunc("DELETE /delete", h.DeleteHandler)
}
