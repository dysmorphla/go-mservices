package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (r *UserRepository) CreateUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	var ID uuid.UUID

	query := `
        INSERT INTO auth.users (email, password_hash, created_at)
        VALUES ($1, $2, NOW())
        RETURNING id;
    `

	err := r.db.QueryRow(ctx, query, email, passwordHash).Scan(&ID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return uuid.Nil, ErrUserAlreadyExists
		}
		return uuid.Nil, err
	}
	return ID, nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return r.getUser(ctx, `
        SELECT id, email, password_hash
        FROM auth.users
        WHERE email = $1 AND deleted_at IS NULL
    `, email)
}

func (r *UserRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (*User, error) {
	return r.getUser(ctx, `
        SELECT id, email, password_hash
        FROM auth.users
        WHERE id = $1 AND deleted_at IS NULL
    `, userID)
}

func (r *UserRepository) GetUserIDBySession(ctx context.Context, sessionID uuid.UUID) (uuid.UUID, error) {
	var userID uuid.UUID

	query := `
		SELECT user_id
		FROM auth.sessions
		WHERE id = $1
		  AND revoked_at IS NULL
	`

	err := r.db.QueryRow(ctx, query, sessionID).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrSessionNotFound
		}
		return uuid.Nil, err
	}
	return userID, nil
}

func (r *UserRepository) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	return execAffectingOne(ctx, r.db, `
		UPDATE auth.users
		SET deleted_at = NOW()
		WHERE id = $1
			AND deleted_at IS NULL;
	`, ErrUserNotFound, userID)
}

//

func (r *UserRepository) CreateSession(ctx context.Context, userID uuid.UUID, userAgent, ip string) (uuid.UUID, error) {
	var ID uuid.UUID

	query := `
		INSERT INTO auth.sessions(
		user_id, user_agent, ip, created_at)
		VALUES ($1, $2, $3, NOW())
		RETURNING id;
	`

	err := r.db.QueryRow(ctx, query, userID, userAgent, ip).Scan(&ID)
	if err != nil {
		return uuid.Nil, err
	}

	return ID, nil
}

func (r *UserRepository) GetSession(ctx context.Context, userID uuid.UUID, userAgent, ip string) (*Session, error) {
	session := &Session{}

	query := `
		SELECT id, user_id, user_agent, ip
		FROM auth.sessions
		WHERE user_id=$1 AND user_agent=$2 AND ip=$3 AND revoked_at IS NULL
		LIMIT 1;
	`

	err := r.db.QueryRow(ctx, query, userID, userAgent, ip).Scan(
		&session.ID, &session.UserID, &session.UserAgent, &session.IP,
	)

	if err != nil {
		return nil, err
	}

	return session, nil
}

func (r *UserRepository) IsSessionActive(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	var active bool

	query := `
		SELECT EXISTS (
			SELECT 1
			FROM auth.sessions
			WHERE id = $1
			  AND revoked_at IS NULL
		);
	`

	err := r.db.QueryRow(ctx, query, sessionID).Scan(&active)
	return active, err
}

func (r *UserRepository) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	return execAffectingOne(ctx, r.db, `
        UPDATE auth.sessions
        SET revoked_at = NOW()
        WHERE id = $1 AND revoked_at IS NULL
    `, ErrSessionNotFound, sessionID)
}

func (r *UserRepository) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	return execAffectingOne(ctx, r.db, `
		UPDATE auth.sessions
		SET revoked_at = NOW()
		WHERE user_id = $1
		  AND revoked_at IS NULL;
	`, ErrSessionNotFound, userID)
}

//

func (r *UserRepository) CreateRefreshToken(ctx context.Context, sessionID uuid.UUID, refreshToken string, expDays int) (uuid.UUID, error) {
	var ID uuid.UUID

	query := `
		INSERT INTO auth.refresh_tokens (session_id, token, created_at, expires_at)
		VALUES ($1, $2, NOW(), NOW() + ($3 * INTERVAL '1 day'))
		RETURNING id;
	`

	err := r.db.QueryRow(ctx, query, sessionID, refreshToken, expDays).Scan(&ID)
	if err != nil {
		return uuid.Nil, err
	}
	return ID, nil
}

func (r *UserRepository) GetRefreshToken(ctx context.Context, refreshToken string) (*RefreshToken, error) {
	rt := &RefreshToken{}

	query := `
		SELECT id, session_id, token, expires_at, revoked_at
		FROM auth.refresh_tokens
		WHERE token = $1
		LIMIT 1;
	`

	err := r.db.QueryRow(ctx, query, refreshToken).Scan(&rt.ID, &rt.SessionID, &rt.Token, &rt.ExpiresAt, &rt.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, err
	}

	return rt, nil
}

func (r *UserRepository) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	return execAffectingOne(ctx, r.db, `
		UPDATE auth.refresh_tokens
		SET revoked_at = NOW()
		WHERE token = $1
			AND revoked_at IS NULL
    `, ErrRefreshTokenNotFound, refreshToken)
}

func (r *UserRepository) RevokeRefreshTokenBySession(ctx context.Context, sessionID uuid.UUID) error {
	return execAffectingOne(ctx, r.db, `
		UPDATE auth.refresh_tokens
		SET revoked_at = NOW()
		WHERE session_id = $1
			AND revoked_at IS NULL;
	`, ErrRefreshTokenNotFound, sessionID)
}

func (r *UserRepository) RevokeAllRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	return execAffectingOne(ctx, r.db, `
		UPDATE auth.refresh_tokens rt
		SET revoked_at = NOW()
		FROM auth.sessions s
		WHERE s.user_id = $1
		  	AND rt.session_id = s.id
		  	AND rt.revoked_at IS NULL;
	`, ErrRefreshTokenNotFound, userID)
}
