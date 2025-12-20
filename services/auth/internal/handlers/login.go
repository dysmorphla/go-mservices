package servicehttp

import (
	"encoding/json"
	"net"
	"net/http"
)

func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req RequestStruct
	req.IP, _, _ = net.SplitHostPort(r.RemoteAddr)

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, ErrBadRequest)
		return
	}

	email, err := validateEmailAndPassword(req)
	if err != nil {
		respondError(w, ErrUnauthorized)
		return
	}

	user, err := h.UserRepo.GetUserByEmail(r.Context(), email.Address)
	if err != nil {
		respondError(w, ErrUnauthorized)
		return
	}

	if err := checkPasswordHash(user.PasswordHash, req.Password); err != nil {
		respondError(w, ErrUnauthorized)
		return
	}

	if session, err := h.UserRepo.GetSession(
		r.Context(), user.ID, r.UserAgent(), req.IP,
	); err == nil {
		_ = h.UserRepo.RevokeSession(r.Context(), session.ID)
		_ = h.UserRepo.RevokeRefreshTokenBySession(r.Context(), session.ID)
	}

	sessionID, err := h.UserRepo.CreateSession(
		r.Context(), user.ID, r.UserAgent(), req.IP,
	)
	if err != nil {
		respondError(w, nil)
		return
	}

	tokens, err := h.issueNewTokens(r.Context(), user.ID, sessionID)
	if err != nil {
		respondError(w, nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}
