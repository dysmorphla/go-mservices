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
	mux.HandleFunc("POST /auth/register", h.RegisterHandler)
	mux.HandleFunc("POST /auth/login", h.LoginHandler)
	mux.HandleFunc("POST /auth/refresh", h.RefreshHandler)
	mux.HandleFunc("POST /auth/logout", h.LogoutHandler)
	mux.HandleFunc("DELETE /auth/delete", h.DeleteHandler)
}
