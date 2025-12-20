package servicehttp

import (
	"encoding/json"
	"net/http"
	"time"
)

func (h *Handler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		respondError(w, ErrUnauthorized)
		return
	}

	rt, err := h.UserRepo.GetRefreshToken(r.Context(), cookie.Value)
	if err != nil || rt.RevokedAt != nil || time.Now().After(rt.ExpiresAt) {
		respondError(w, ErrUnauthorized)
		return
	}

	active, err := h.UserRepo.IsSessionActive(r.Context(), rt.SessionID)
	if err != nil || !active {
		respondError(w, ErrUnauthorized)
		return
	}

	_ = h.UserRepo.RevokeRefreshToken(r.Context(), cookie.Value)

	userID, err := h.UserRepo.GetUserIDBySession(r.Context(), rt.SessionID)
	if err != nil {
		respondError(w, ErrUnauthorized)
		return
	}

	tokens, err := h.issueNewTokens(r.Context(), userID, rt.SessionID)
	if err != nil {
		respondError(w, nil)
		return
	}

	json.NewEncoder(w).Encode(tokens)
}
