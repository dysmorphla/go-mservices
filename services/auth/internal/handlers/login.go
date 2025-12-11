package servicehttp

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req RequestStruct
	req.IP, _, _ = net.SplitHostPort(r.RemoteAddr)

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

	session, err := h.UserRepo.GetExistingSession(r.Context(), user.ID, r.UserAgent(), req.IP)
	if err != nil && err != pgx.ErrNoRows {
		http.Error(w, "session lookup failed", http.StatusInternalServerError)
		return
	}

	var sessionID uuid.UUID

	if session != nil {
		sessionID = session.ID
	} else {
		sessionID, err = h.UserRepo.CreateSession(r.Context(), user.ID, r.UserAgent(), req.IP)
		if err != nil {
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}
	}

	tokens, err := h.issueTokens(r.Context(), user.ID, sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokens)

}
