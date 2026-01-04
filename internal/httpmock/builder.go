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
type BuildablePathConfig interface {
	Build() PathConfig
}

type LinearResponse struct {
	Responses []Response
}

type TextResponse struct {
	Text   string
	Status int
}

type CustomResponse struct {
	Status      int
	ContentType string
	Body        string
}

func (r *TextResponse) SetStatus(status int) {
	r.Status = status
}

type JsonResponse struct {
	Raw    interface{}
	Text   string
	Status int
}

func (r *JsonResponse) SetStatus(status int) {
	r.Status = status
}

type FuncResponse struct {
	Text    func(CustomParam, *http.Request) string
	Json    func(CustomParam, *http.Request) interface{}
	Handler func(CustomParam, http.ResponseWriter, *http.Request)
}

type PathConfig struct {
	Path   string
	Method map[string]Response
}

type EntryStatus struct {
	CallCount      map[string]int
	LinearPosition map[string]int
}

type CustomParam struct {
	Count int
}

type PathConfigBuilder struct {
	PathConfig PathConfig
	building   building
}

type building struct {
	method    string
	responses []CustomResponse
}

func Path(path string) *PathConfigBuilder {
	return &PathConfigBuilder{
		PathConfig: PathConfig{
			Path:   path,
			Method: make(map[string]Response),
		},
	}
}

func (b *PathConfigBuilder) Get() *PathConfigBuilder {
	b.applyToPathConfig()
	b.building.method = http.MethodGet
	return b
}

func (b *PathConfigBuilder) Delete() *PathConfigBuilder {
	b.applyToPathConfig()
	b.building.method = http.MethodDelete
	return b
}

func (b *PathConfigBuilder) Put() *PathConfigBuilder {
	b.applyToPathConfig()
	b.building.method = http.MethodPut
	return b
}

func (b *PathConfigBuilder) Post() *PathConfigBuilder {
	b.applyToPathConfig()
	b.building.method = http.MethodPost
	return b
}

func (b *PathConfigBuilder) Text(text string) *PathConfigBuilder {
	if b.building.method == "" {
		b.Get()
	}
	b.building.responses = append(
		b.building.responses,
		CustomResponse{
			Body:        text,
			ContentType: "text/plain; charset=utf-8",
		},
	)
	return b
}

func (b *PathConfigBuilder) Json(data interface{}) *PathConfigBuilder {
	if b.building.method == "" {
		b.Get()
	}
	j, err := json.Marshal(data)
	if err != nil {
		panic(fmt.Sprintf("Cannot json.marshal(): %v", data))
	}
	b.building.responses = append(
		b.building.responses,
		CustomResponse{
			Body:        string(j),
			ContentType: "application/json; charset=utf-8",
		},
	)
	return b
}

func (b *PathConfigBuilder) Status(status int) *PathConfigBuilder {
	b.building.responses[len(b.building.responses)-1].Status = status
	return b
}

func (b *PathConfigBuilder) applyToPathConfig() {
	if b.building.method == "" {
		return
	}
	b.PathConfig.Method[b.building.method] = b.building.responses
	b.building = building{}
}

func (b *PathConfigBuilder) Build() PathConfig {
	b.applyToPathConfig()
	return b.PathConfig
}

func (p PathConfig) Build() PathConfig {
	return p
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
	if r.Status != 0 {
		w.WriteHeader(r.Status)
	}
	io.WriteString(w, r.Text)
}

func handleJson(r JsonResponse, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Status != 0 {
		w.WriteHeader(r.Status)
	}

	if r.Raw != nil {
		if err := json.NewEncoder(w).Encode(r.Raw); err != nil {
			panic(fmt.Sprintf("Failed to encode to json format: %v", r.Raw))
		}
	} else {
		io.WriteString(w, r.Text)
	}
}

func handleCustom(r CustomResponse, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", r.ContentType)
	if r.Status != 0 {
		w.WriteHeader(r.Status)
	}
	io.WriteString(w, r.Body)
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

func handleRequest(config PathConfig, entryStatus *EntryStatus, w http.ResponseWriter, r *http.Request) {
	entryStatus.CallCount[r.Method]++
	count := entryStatus.CallCount[r.Method]

	response, ok := config.Method[r.Method]
	if !ok {
		panic(fmt.Sprintf("Method %s for %s not configured.", r.Method, config.Path))
	}

	processResponse(config, entryStatus, count, response, w, r)
}

func processResponse(
	config PathConfig, entryStatus *EntryStatus,
	count int, response Response,
	w http.ResponseWriter, r *http.Request,
) {
	switch res := response.(type) {
	case TextResponse:
		handleText(res, w, r)
	case JsonResponse:
		handleJson(res, w, r)
	case CustomResponse:
		handleCustom(res, w, r)
	case FuncResponse:
		handleFunc(res, count, w, r)
	case []Response:
		processResponse(config, entryStatus, count, LinearResponse{Responses: res}, w, r)
	case []CustomResponse:
		t := make([]Response, len(res))
		for i, v := range res {
			t[i] = v
		}
		processResponse(config, entryStatus, count, LinearResponse{Responses: t}, w, r)
	case LinearResponse:
		r2 := res.Responses[entryStatus.LinearPosition[r.Method]%len(res.Responses)]
		if _, ok := r2.(LinearResponse); ok {
			panic(fmt.Sprintf("LinearResponse in LinearResponse is not supported. (%s)", config.Path))
		}
		entryStatus.LinearPosition[r.Method]++
		processResponse(config, entryStatus, count, r2, w, r)
	default:
		panic(fmt.Sprintf("Unknown Response type: %T", response))
	}
}

func Start(configs []BuildablePathConfig) Server {
	mux := http.NewServeMux()

	for _, buildable := range configs {
		config := buildable.Build()

		entryStatus := EntryStatus{
			CallCount:      make(map[string]int),
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
