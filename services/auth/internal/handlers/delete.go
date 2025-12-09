package servicehttp

import (
	"encoding/json"
	"net/http"
)

func (h *Handler) DeleteHandler(w http.ResponseWriter, r *http.Request) {
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

	user, err := h.CheckPassword(email.Address, req.Password, r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	err = h.UserRepo.DeleteUserByEmail(r.Context(), email.Address)
	if err != nil {
		http.Error(w, "failed delete user: "+err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}
