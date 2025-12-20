package servicehttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/ncundstnd/go-mservices/services/auth/internal/config"
	"golang.org/x/crypto/bcrypt"
)

type RequestStruct struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	IP       string `json:"ip"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	jwt.RegisteredClaims
}

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrConflict     = errors.New("conflict")
	ErrBadRequest   = errors.New("bad request")
)

func respondError(w http.ResponseWriter, err error) {
	switch err {
	case ErrBadRequest:
		http.Error(w, "bad request", http.StatusBadRequest)
	case ErrUnauthorized:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case ErrForbidden:
		http.Error(w, "forbidden", http.StatusForbidden)
	case ErrConflict:
		http.Error(w, "conflict", http.StatusConflict)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) parseAccessToken(r *http.Request) (*Claims, error) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		return nil, ErrUnauthorized
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(
		cookie.Value,
		claims,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrUnauthorized
			}
			return []byte(h.Cfg.JWT.Secret), nil
		},
	)

	if err != nil || !token.Valid {
		return nil, ErrUnauthorized
	}

	return claims, nil
}

func validateEmailAndPassword(req RequestStruct) (*mail.Address, error) {
	if req.Email == "" || req.Password == "" {
		return nil, fmt.Errorf("email and password required")
	}

	email, err := mail.ParseAddress(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid email format")
	}

	return email, nil
}

func checkPasswordHash(hash, password string) error {
	if err := bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(password),
	); err != nil {
		return errors.New("invalid credentials")
	}
	return nil
}

func generateJWT(userID, sessionID string, cfg *config.JWTConfig) (string, error) {
	claims := Claims{
		UserID:    userID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(
				time.Now().Add(time.Minute * time.Duration(cfg.ExpMinutes)),
			),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.Secret))
}

func generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func (h *Handler) issueNewTokens(ctx context.Context, userID, sessionID uuid.UUID) (*TokenPair, error) {
	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	accessToken, err := generateJWT(userID.String(), sessionID.String(), &h.Cfg.JWT)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	_, err = h.UserRepo.CreateRefreshToken(ctx, sessionID, refreshToken, 14)
	if err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
