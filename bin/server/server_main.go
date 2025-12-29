package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"go-parts/internal/server"
)

func main() {
	mux := server.CreateMux()
	handler := server.NewCorsMiddleware(mux, []string{"http://localhost:8080"})
	fmt.Println("Server Start.")
	err := http.ListenAndServe(":8080", handler)
	if err != nil {
		slog.Error("some errors", "error", err)
	}
}
