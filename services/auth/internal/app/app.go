package app

import (
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncundstnd/go-mservices/services/auth/internal/config"
	servicehttp "github.com/ncundstnd/go-mservices/services/auth/internal/handlers"
	"github.com/ncundstnd/go-mservices/services/auth/internal/repository"
)

type App struct {
	httpServer *http.Server
	cfg        *config.Config
	db         *pgxpool.Pool
}

func New() (*App, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}

	db, err := repository.NewPostgres(cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("failed to init postgres: %w", err)
	}

	userRepo := repository.NewUserRepository(db)
	handler := &servicehttp.Handler{
		UserRepo: userRepo,
		Cfg:      cfg,
	}

	mux := http.NewServeMux()
	servicehttp.RegisterRoutes(mux, handler)

	a := &App{
		cfg: cfg,
		db:  db,
		httpServer: &http.Server{
			Addr:    ":" + cfg.HTTP.Port,
			Handler: mux,
		},
	}

	return a, nil
}

func (a *App) Run() error {
	fmt.Printf("Auth service is running on : %s\n", a.cfg.HTTP.Port)
	return a.httpServer.ListenAndServe()
}
