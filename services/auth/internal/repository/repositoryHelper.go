package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	db *pgxpool.Pool
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

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrSessionNotFound      = errors.New("session not found or revoked")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
)

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) getUser(ctx context.Context, query string, arg any) (*User, error) {
	user := &User{}

	err := r.db.QueryRow(ctx, query, arg).
		Scan(&user.ID, &user.Email, &user.PasswordHash)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

func execAffectingOne(ctx context.Context, db *pgxpool.Pool, query string, notFoundErr error, args ...any) error {
	cmd, err := db.Exec(ctx, query, args...)
	if err != nil {
		return err
	}

	if cmd.RowsAffected() == 0 {
		return notFoundErr
	}

	return nil
}
