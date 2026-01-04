package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"go-parts/internal/server"
)

func main() {
	cors := []string{"http://localhost:8080"}
	mux := server.CreateMux()
	mux.Handle("/frontend/", http.StripPrefix("/frontend/", http.FileServer(http.Dir("./frontend"))))
	mux.Handle("/ws", server.NewWsEchoHttpHandler(cors))

	handler := server.NewCorsMiddleware(mux, cors)

	fmt.Println("Server Start.")
	err := http.ListenAndServe(":8080", handler)
	if err != nil {
		slog.Error("some errors", "error", err)
	}
}
