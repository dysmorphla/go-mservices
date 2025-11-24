package app

import (
	"fmt"
	nethttp "net/http"

	"github.com/ncundstnd/go-mservices/services/auth/internal/config"
	deliveryhttp "github.com/ncundstnd/go-mservices/services/auth/internal/delivery"
)

type App struct {
	httpServer *nethttp.Server
	cfg        *config.Config
}

func New() (*App, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}

	//чё это бля
	mux := nethttp.NewServeMux()
	deliveryhttp.RegisterRoutes(mux)

	a := &App{
		cfg: cfg,
		httpServer: &nethttp.Server{
			Addr:    ":" + cfg.HTTP.Port,
			Handler: mux,
		},
	}

	return a, nil
}

func (a *App) Run() error {
	fmt.Printf("Auth service is running on : %s \n", a.cfg.HTTP.Port)
	return a.httpServer.ListenAndServe()
}
