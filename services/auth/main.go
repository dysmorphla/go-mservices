package main

import (
	"log"

	"github.com/ncundstnd/go-mservices/services/auth/internal/app"
)

func main() {
	a, err := app.New()
	if err != nil {
		log.Fatalf("failed to init app: %v", err)
	}

	if err := a.Run(); err != nil {
		log.Fatalf("app stopped: %v", err)
	}
}
