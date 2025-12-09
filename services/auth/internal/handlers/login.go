package servicehttp

import (
	"encoding/json"
	"net/http"
)

func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
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

	token, err := GenerateJWT(user.ID.String(), &h.Cfg.JWT)
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	//Подумать над временем
	tokenID, err := h.UserRepo.CreateToken(r.Context(), user.ID, token, 1440)
	if err != nil {
		http.Error(w, "failed to save refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenID)
}
