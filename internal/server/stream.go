package server

import (
	"fmt"
	"net/http"
	"time"
)

func writeGreetingStream(w http.ResponseWriter, flusher http.Flusher, sleep func(time.Duration)) {
	fmt.Fprintf(w, "Hello.\n")
	flusher.Flush()
	sleep(1 * time.Second)

	fmt.Fprintf(w, "This is ")
	flusher.Flush()
	sleep(1 * time.Second)

	fmt.Fprintf(w, "streaming handler.\n")
	flusher.Flush()
}

func greetingStreamHandler(w http.ResponseWriter, _ *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	writeGreetingStream(w, flusher, time.Sleep)
}
