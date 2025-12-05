package servicehttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "email and password required", http.StatusBadRequest)
		return
	}

	email, err := mail.ParseAddress(req.Email)
	if err != nil {
		http.Error(w, "email incorrect", http.StatusBadRequest)
		return
	}

	user, err := h.UserRepo.GetUserByEmail(r.Context(), email.Address)
	if err != nil {
		http.Error(w, "failed to get user: "+err.Error(), http.StatusConflict)
		return
	}

	fmt.Printf(user.ID, user.Email, user.PasswordHash)
}
