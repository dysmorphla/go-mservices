package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(ctx context.Context, email, password string) (string, error) {
	// хэшируем пароль
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	var userID string

	query := `
        INSERT INTO auth.users (email, password_hash, created_at, updated_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id;
    `

	err = r.db.QueryRow(ctx, query, email, string(hash), time.Now(), time.Now()).Scan(&userID)
	if err != nil {
		// проверка на нарушение уникальности email
		// if pgErr, ok := err.(*pgxpool.PoolError); ok {
		// 	return "", pgErr
		// }
		return "", err
	}

	return userID, nil
}
