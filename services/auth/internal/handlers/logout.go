package servicehttp

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
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

	active, err := h.UserRepo.IsSessionActive(r.Context(), sessionID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if !active {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	_ = h.UserRepo.RevokeSession(r.Context(), sessionID)
	_ = h.UserRepo.RevokeRefreshTokenBySession(r.Context(), sessionID)

	w.WriteHeader(http.StatusNoContent)
}
