package servicehttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/mail"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ncundstnd/go-mservices/services/auth/internal/config"
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

func GenerateJWT(userID string, cfg *config.JWTConfig) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Minute * time.Duration(cfg.ExpMinutes)).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Secret))
}

func GenerateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func CompareRefreshTokens() {

}
