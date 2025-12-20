package servicehttp

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

func (h *Handler) DeleteHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims, err := h.parseAccessToken(r)
	if err != nil {
		respondError(w, err)
		return
	}

	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil {
		respondError(w, ErrUnauthorized)
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		respondError(w, ErrUnauthorized)
		return
	}

	active, err := h.UserRepo.IsSessionActive(ctx, sessionID)
	if err != nil || !active {
		respondError(w, ErrUnauthorized)
		return
	}

	user, err := h.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		respondError(w, ErrUnauthorized)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		respondError(w, ErrBadRequest)
		return
	}

	if err := checkPasswordHash(user.PasswordHash, req.Password); err != nil {
		respondError(w, ErrUnauthorized)
		return
	}

	// best-effort cleanup
	_ = h.UserRepo.RevokeAllRefreshTokens(ctx, userID)
	_ = h.UserRepo.RevokeAllSessions(ctx, userID)

	if err := h.UserRepo.DeleteUser(ctx, userID); err != nil {
		respondError(w, ErrConflict)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
