package servicehttp

import (
	"net/http"

	"github.com/ncundstnd/go-mservices/services/auth/internal/repository"
)

type Handler struct {
	UserRepo *repository.UserRepository
}

func RegisterRoutes(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("/ping", PingHandler)
	mux.HandleFunc("/register", h.RegisterHandler)
	mux.HandleFunc("/login", LoginHandler)
	mux.HandleFunc("/reset", ResetHandler)

}
