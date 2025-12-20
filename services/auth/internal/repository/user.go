package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
}

type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	UserAgent string
	IP        string
}

type RefreshToken struct {
	ID        uuid.UUID
	SessionID uuid.UUID
	Token     string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

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
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				return uuid.Nil, errors.New("email already exists")
			}
		}
		return uuid.Nil, err
	}
	return ID, nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user := &User{}

	query := `
        SELECT id, email, password_hash
        FROM auth.users
		WHERE email = $1
  			AND deleted_at IS NULL
    `

	err := r.db.QueryRow(ctx, query, email).Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	user := &User{}

	query := `
        SELECT id, email, password_hash
        FROM auth.users
		WHERE id = $1
  			AND deleted_at IS NULL
    `

	err := r.db.QueryRow(ctx, query, id).Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return user, nil
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
			return uuid.Nil, errors.New("session not found or revoked")
		}
		return uuid.Nil, err
	}

	return userID, nil
}

func (r *UserRepository) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE auth.users
		SET deleted_at = NOW()
		WHERE id = $1
			AND deleted_at IS NULL;
	`

	cmd, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return err
	}

	if cmd.RowsAffected() == 0 {
		return errors.New("user not found or already deleted")
	}

	return nil
}

//

func (r *UserRepository) CreateSession(ctx context.Context, id uuid.UUID, userAgent, ip string) (uuid.UUID, error) {
	var ID uuid.UUID

	query := `
		INSERT INTO auth.sessions(
		user_id, user_agent, ip, created_at)
		VALUES ($1, $2, $3, NOW())
		RETURNING id;
	`

	err := r.db.QueryRow(ctx, query, id, userAgent, ip).Scan(&ID)
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
	query := `
		UPDATE auth.sessions
		SET revoked_at = NOW()
		WHERE id = $1
		  	AND revoked_at IS NULL;
	`

	cmd, err := r.db.Exec(ctx, query, sessionID)
	if err != nil {
		return err
	}

	if cmd.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}

	return nil
}

func (r *UserRepository) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE auth.sessions
		SET revoked_at = NOW()
		WHERE user_id = $1
		  AND revoked_at IS NULL;
	`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}

//

func (r *UserRepository) CreateRefreshToken(ctx context.Context, id uuid.UUID, refreshToken string, expDays int) (uuid.UUID, error) {
	var ID uuid.UUID

	query := `
		INSERT INTO auth.refresh_tokens (session_id, token, created_at, expires_at)
		VALUES ($1, $2, NOW(), NOW() + ($3 * INTERVAL '1 day'))
		RETURNING id;
	`

	err := r.db.QueryRow(ctx, query, id, refreshToken, expDays).Scan(&ID)
	if err != nil {
		return uuid.Nil, err
	}
	return ID, nil
}

func (r *UserRepository) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	rt := &RefreshToken{}

	query := `
		SELECT id, session_id, token, expires_at, revoked_at
		FROM auth.refresh_tokens
		WHERE token = $1
		LIMIT 1;
	`

	err := r.db.QueryRow(ctx, query, token).Scan(&rt.ID, &rt.SessionID, &rt.Token, &rt.ExpiresAt, &rt.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("refresh token not found")
		}
		return nil, err
	}

	return rt, nil
}

func (r *UserRepository) RevokeRefreshToken(ctx context.Context, token string) error {
	query := `
		UPDATE auth.refresh_tokens
		SET revoked_at = NOW()
		WHERE token = $1
			AND revoked_at IS NULL;
	`

	cmd, err := r.db.Exec(ctx, query, token)
	if err != nil {
		return err
	}

	if cmd.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}

	return nil
}

func (r *UserRepository) RevokeRefreshTokenBySession(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE auth.refresh_tokens
		SET revoked_at = NOW()
		WHERE session_id = $1
			AND revoked_at IS NULL;
	`

	cmd, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return err
	}

	if cmd.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}

	return nil
}

func (r *UserRepository) RevokeAllRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE auth.refresh_tokens rt
		SET revoked_at = NOW()
		FROM auth.sessions s
		WHERE s.user_id = $1
		  AND rt.session_id = s.id
		  AND rt.revoked_at IS NULL;
	`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}
