package repository

import (
	"context"
	"errors"

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
	Email        string
	PasswordHash string
	ID           uuid.UUID
}

func (r *UserRepository) CreateUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	var ID uuid.UUID

	query := `
        INSERT INTO auth.users (email, password_hash, created_at, updated_at)
        VALUES ($1, $2, NOW(), NOW())
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

func (r *UserRepository) DeleteUserByEmail(ctx context.Context, email string) error {
	query := `DELETE FROM auth.users WHERE email = $1`
	cmdTag, err := r.db.Exec(ctx, query, email)
	if err != nil {
		return err
	}

	if cmdTag.RowsAffected() == 0 {
		return errors.New("user not found")
	}

	return nil
}

func (r *UserRepository) CreateToken(ctx context.Context, id uuid.UUID, token string, expMinutes int) (uuid.UUID, error) {
	var ID uuid.UUID

	query := `
		INSERT INTO auth.refresh_tokens (user_id, token, created_at, expires_at)
		VALUES ($1, $2, NOW(), NOW() + ($3 || ' minutes')::interval)
		RETURNING id;
	`

	err := r.db.QueryRow(ctx, query, id, token, expMinutes).Scan(&ID)
	if err != nil {
		return uuid.Nil, err
	}
	return ID, nil
}

func (r *UserRepository) CreateSession(ctx context.Context) (uuid.UUID, error) {

	return uuid.Nil, nil
}
