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

	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	accessToken, err := GenerateJWT(user.ID.String(), &h.Cfg.JWT)
	if err != nil {
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	//Подумать
	_, err = h.UserRepo.CreateRefreshToken(r.Context(), user.ID, refreshToken, 14)
	if err != nil {
		http.Error(w, "failed to save refresh token", http.StatusInternalServerError)
		return
	}

	resp := struct {
		AcceccToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}{
		AcceccToken:  accessToken,
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}
