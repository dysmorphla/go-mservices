package servicehttp

import (
	"net/http"

	"github.com/google/uuid"
)

func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := h.parseAccessToken(r)
	if err != nil {
		respondError(w, err)
		return
	}

	sessionID, _ := uuid.Parse(claims.SessionID)

	active, err := h.UserRepo.IsSessionActive(r.Context(), sessionID)
	if err != nil || !active {
		respondError(w, ErrUnauthorized)
		return
	}

	_ = h.UserRepo.RevokeSession(r.Context(), sessionID)
	_ = h.UserRepo.RevokeRefreshTokenBySession(r.Context(), sessionID)

	w.WriteHeader(http.StatusNoContent)
}
