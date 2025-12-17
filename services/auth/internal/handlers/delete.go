package servicehttp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (h *Handler) DeleteHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. JWT
	cookie, err := r.Cookie("access_token")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	tokenStr := cookie.Value

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(h.Cfg.JWT.Secret), nil
		},
	)

	if err != nil || !token.Valid {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sessionID, _ := uuid.Parse(claims.SessionID)
	userID, _ := uuid.Parse(claims.UserID)

	active, err := h.UserRepo.IsSessionActive(ctx, sessionID)
	if err != nil || !active {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.UserRepo.GetUserByID(ctx, userID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if err := CheckPasswordHash(user.PasswordHash, req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	_ = h.UserRepo.RevokeAllRefreshTokens(ctx, userID)
	_ = h.UserRepo.RevokeAllSessions(ctx, userID)

	if err := h.UserRepo.DeleteUser(ctx, userID); err != nil {
		http.Error(w, "failed delete user", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
