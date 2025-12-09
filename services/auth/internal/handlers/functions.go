package servicehttp

import (
	"context"
	"fmt"
	"net/mail"

	"github.com/ncundstnd/go-mservices/services/auth/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

type RequestStruct struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func ValidateEmailAndPassword(req RequestStruct) (*mail.Address, error) {
	if req.Email == "" || req.Password == "" {
		return nil, fmt.Errorf("email and password required")
	}

	email, err := mail.ParseAddress(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid email format")
	}

	return email, nil
}

func (h *Handler) CheckPassword(email string, password string, ctx context.Context) (*repository.User, error) {
	user, err := h.UserRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	return user, nil
}
