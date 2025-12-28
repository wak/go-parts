package main

import (
	"go-parts/server"
	"log/slog"
	"net/http"
)

func main() {
	mux := server.CreateMux()
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		slog.Error("some errors", "error", err)
	}
}
