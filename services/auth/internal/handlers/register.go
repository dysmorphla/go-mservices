package servicehttp

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RequestStruct

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	email, err := ValidateEmailAndPassword(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	userID, err := h.UserRepo.CreateUser(r.Context(), email.Address, string(passwordHash))
	if err != nil {
		http.Error(w, "failed to create user: "+err.Error(), http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"id":"` + userID.String() + `"}`))
}
