package servicehttp

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {

	sessionID, ok := r.Context().Value("session_id").(uuid.UUID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.UserRepo.RevokeSession(r.Context(), sessionID); err != nil && err != pgx.ErrNoRows {
		http.Error(w, "failed to revoke session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
