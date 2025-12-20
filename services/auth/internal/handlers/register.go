package servicehttp

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (h *Handler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RequestStruct

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, ErrBadRequest)
		return
	}

	email, err := validateEmailAndPassword(req)
	if err != nil {
		respondError(w, ErrBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, nil)
		return
	}

	userID, err := h.UserRepo.CreateUser(r.Context(), email.Address, string(hash))
	if err != nil {
		respondError(w, ErrConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"id": userID.String(),
	})
}
