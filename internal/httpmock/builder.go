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

type LinearResponse struct {
	Responses []Response
}

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

type EntryStatus struct {
	GetCount       int
	LinearPosition map[string]int
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

func handleRequest(config EntryConfig, entryStatus *EntryStatus, w http.ResponseWriter, r *http.Request) {
	var count int
	var response Response

	switch r.Method {
	case http.MethodGet:
		response = config.GetMethod
		entryStatus.GetCount++
		count = entryStatus.GetCount
	default:
		panic(fmt.Sprintf("Method %s not implement.", r.Method))
	}
	if response == nil {
		panic(fmt.Sprintf("Method %s for %s not configured.", r.Method, config.Path))
	}
	processResponse(config, entryStatus, count, response, w, r)
}

func processResponse(
	config EntryConfig, entryStatus *EntryStatus,
	count int, response Response,
	w http.ResponseWriter, r *http.Request,
) {
	switch res := response.(type) {
	case TextResponse:
		handleText(res, w, r)
	case JsonResponse:
		handleJson(res, w, r)
	case FuncResponse:
		handleFunc(res, count, w, r)
	case LinearResponse:
		if _, ok := entryStatus.LinearPosition[r.Method]; !ok {
			entryStatus.LinearPosition[r.Method] = 0
		}

		r2 := res.Responses[entryStatus.LinearPosition[r.Method]%len(res.Responses)]
		if _, ok := r2.(LinearResponse); ok {
			panic(fmt.Sprintf("LinearResponse in LinearResponse is not supported. (%s)", config.Path))
		}
		entryStatus.LinearPosition[r.Method]++
		processResponse(config, entryStatus, count, r2, w, r)
	}
}

func Start(configs []EntryConfig) Server {
	mux := http.NewServeMux()

	for _, config := range configs {
		entryStatus := EntryStatus{
			LinearPosition: make(map[string]int),
		}
		handler := func(w http.ResponseWriter, r *http.Request) {
			handleRequest(config, &entryStatus, w, r)
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
