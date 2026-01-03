package httpmock

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
)

type Server struct {
	URL    string
	server *httptest.Server
}

type Response interface{}

// type Response struct {
// 	Text        *string
// 	Json        interface{}
// 	JsonText    *string
// 	FuncText    func(CustomParam, *http.Request) string
// 	FuncJsonRaw func(CustomParam, *http.Request) interface{}
// 	FuncHandler func(CustomParam, http.ResponseWriter, *http.Request)
// }

// func S(s string) *string {
// 	return &s
// }

type TextResponse struct {
	Text string
}

type JsonResponse struct {
	Raw  interface{}
	Text string
}

type FuncResponse struct {
	Text    func(CustomParam, *http.Request) string
	Json    func(CustomParam, *http.Request) interface{}
	Handler func(CustomParam, http.ResponseWriter, *http.Request)
}

type EntryConfig struct {
	Path      string
	GetMethod Response
}

type Count struct {
	Get int
}

type CustomParam struct {
	Count int
}

func F(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Failed to open %s: %v", path, err))
	}
	return string(b)
}

func handleText(r TextResponse, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, r.Text)
}

func handleJson(r JsonResponse, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Raw != nil {
		if err := json.NewEncoder(w).Encode(r.Raw); err != nil {
			panic(fmt.Sprintf("Failed to encode to json format: %v", r.Raw))
		}
	} else {
		io.WriteString(w, r.Text)
	}
}

func handleFunc(resp FuncResponse, count int, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	cp := CustomParam{Count: count}
	if resp.Text != nil {
		content := resp.Text(cp, r)
		handleText(TextResponse{Text: content}, w, r)
	} else if resp.Json != nil {
		content := resp.Json(cp, r)
		handleJson(JsonResponse{Raw: content}, w, r)
	} else if resp.Handler != nil {
		resp.Handler(cp, w, r)
	} else {
		panic("No handler defined.")
	}
}

func handleRequest(_ EntryConfig, response Response, count int, w http.ResponseWriter, r *http.Request) {
	switch res := response.(type) {
	case TextResponse:
		handleText(res, w, r)
	case JsonResponse:
		handleJson(res, w, r)
	case FuncResponse:
		handleFunc(res, count, w, r)
	default:
		panic(fmt.Sprintf("Unknown response type: %T", response))
	}
}

func Start(configs []EntryConfig) Server {
	mux := http.NewServeMux()

	for _, config := range configs {
		var count Count
		handler := func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				count.Get++
				handleRequest(config, config.GetMethod, count.Get, w, r)
			default:
				panic(fmt.Sprintf("Method %s for %s not configured.", r.Method, config.Path))
			}
		}

		mux.HandleFunc(config.Path, handler)
	}

	server := httptest.NewServer(mux)
	return Server{
		URL:    server.URL,
		server: server,
	}
}

func (s *Server) Close() {
	s.server.Close()
}
