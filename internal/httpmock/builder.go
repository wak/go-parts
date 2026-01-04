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

type BuildablePathConfig interface {
	Build() PathConfig
}

type ResponseConfig struct {
	Status      int
	ContentType string
	Body        string
	Handler     func(CustomParam, http.ResponseWriter, *http.Request)
}

type PathConfig struct {
	Path   string
	Method map[string][]ResponseConfig
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
	responses []ResponseConfig
}

func Path(path string) *PathConfigBuilder {
	return &PathConfigBuilder{
		PathConfig: PathConfig{
			Path:   path,
			Method: make(map[string][]ResponseConfig),
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
		ResponseConfig{
			Body:        text,
			ContentType: "text/plain; charset=utf-8",
		},
	)
	return b
}

func (b *PathConfigBuilder) Json(data interface{}) *PathConfigBuilder {
	j, err := json.Marshal(data)
	if err != nil {
		panic(fmt.Sprintf("Cannot json.marshal(): %v", data))
	}
	return b.JsonS(string(j))
}

func (b *PathConfigBuilder) JsonS(jsons string) *PathConfigBuilder {
	if b.building.method == "" {
		b.Get()
	}
	b.building.responses = append(
		b.building.responses,
		ResponseConfig{
			Body:        jsons,
			ContentType: "application/json; charset=utf-8",
		},
	)
	return b
}

func (b *PathConfigBuilder) Handler(f func(CustomParam, http.ResponseWriter, *http.Request)) *PathConfigBuilder {
	if b.building.method == "" {
		b.Get()
	}
	b.building.responses = append(
		b.building.responses,
		ResponseConfig{
			Handler: f,
		},
	)
	return b
}

func (b *PathConfigBuilder) Status(status int) *PathConfigBuilder {
	b.building.responses[len(b.building.responses)-1].Status = status
	return b
}

func (b *PathConfigBuilder) ContentType(contentType string) *PathConfigBuilder {
	b.building.responses[len(b.building.responses)-1].ContentType = contentType
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

func F(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Failed to open %s: %v", path, err))
	}
	return string(b)
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
	_ PathConfig, entryStatus *EntryStatus,
	count int, responseConfigs []ResponseConfig,
	w http.ResponseWriter, r *http.Request,
) {
	responseConfig := responseConfigs[entryStatus.LinearPosition[r.Method]%len(responseConfigs)]
	entryStatus.LinearPosition[r.Method]++

	if responseConfig.ContentType != "" {
		w.Header().Set("Content-Type", responseConfig.ContentType)
	}
	if responseConfig.Status != 0 {
		w.WriteHeader(responseConfig.Status)
	}

	cp := CustomParam{Count: count}
	if responseConfig.Handler != nil {
		responseConfig.Handler(cp, w, r)
	} else {
		io.WriteString(w, responseConfig.Body)
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
