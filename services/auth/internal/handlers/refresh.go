package servicehttp

import (
	"encoding/json"
	"net/http"
	"time"
)

func (h *Handler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	refreshToken := cookie.Value

	rt, err := h.UserRepo.GetRefreshToken(r.Context(), refreshToken)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if rt.RevokedAt != nil || time.Now().After(rt.ExpiresAt) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	active, err := h.UserRepo.IsSessionActive(r.Context(), rt.SessionID)
	if err != nil || !active {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	_ = h.UserRepo.RevokeRefreshToken(r.Context(), refreshToken)

	userID, err := h.UserRepo.GetUserIDBySession(r.Context(), rt.SessionID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	tokens, err := h.IssueNewTokens(r.Context(), userID, rt.SessionID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}
