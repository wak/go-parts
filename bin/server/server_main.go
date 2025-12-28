package main

import (
	"log/slog"
	"net/http"

	"go-parts/internal/server"
)

func main() {
	mux := server.CreateMux()
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		slog.Error("some errors", "error", err)
	}
}
