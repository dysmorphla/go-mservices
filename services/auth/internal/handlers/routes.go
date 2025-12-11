package servicehttp

import (
	"net/http"

	"github.com/ncundstnd/go-mservices/services/auth/internal/config"
	"github.com/ncundstnd/go-mservices/services/auth/internal/repository"
)

type Handler struct {
	UserRepo *repository.UserRepository
	Cfg      *config.Config
}

func RegisterRoutes(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("POST /register", h.RegisterHandler)
	mux.HandleFunc("POST /login", h.LoginHandler)
	mux.HandleFunc("POST /refresh", h.RefreshHandler)
	mux.HandleFunc("POST /logout", h.LogoutHandler)
	mux.HandleFunc("DELETE /delete", h.DeleteHandler)
}
