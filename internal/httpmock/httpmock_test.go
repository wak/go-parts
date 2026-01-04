package httpmock

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func get(t *testing.T, url string, path string) string {
	res, err := http.Get(url + path)
	if err != nil {
		t.Fatalf("Failed GET %s", path)
	}
	responseBody, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatalf("Failed to read response of %s", path)
	}
	return string(responseBody)
}

func post(t *testing.T, url string, path string, contentType string, body string) string {
	res, err := http.Post(url+path, contentType, strings.NewReader(body))
	if err != nil {
		t.Fatalf("Failed POST %s: %v", path, err)
	}

	responseBody, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatalf("Failed to read response of %s: %v", path, err)
	}

	return string(responseBody)
}

func Test_ServerRun(t *testing.T) {
	server := Start([]BuildablePathConfig{
		PathConfig{
			Path: "/text",
			Method: map[string]Response{
				http.MethodGet: []Response{TextResponse{Text: "sample text"}},
			},
		},
		PathConfig{
			Path: "/json_r",
			Method: map[string]Response{
				http.MethodGet: JsonResponse{
					Raw: map[string]interface{}{
						"path":  "/json",
						"value": "json raw",
					},
				},
			},
		},
		PathConfig{
			Path: "/json_t",
			Method: map[string]Response{
				http.MethodGet: JsonResponse{Text: "123"},
			},
		},
		PathConfig{
			Path: "/linear",
			Method: map[string]Response{
				http.MethodGet: LinearResponse{
					Responses: []Response{
						TextResponse{Text: "text 1"},
						TextResponse{Text: "text 2"},
						TextResponse{Text: "text 3"},
					},
				},
			},
		},
		PathConfig{
			Path: "/custom_t",
			Method: map[string]Response{
				http.MethodGet: FuncResponse{
					Text: func(c CustomParam, _ *http.Request) string {
						return fmt.Sprintf("custom_t %d", c.Count)
					},
				},
			},
		},
		PathConfig{
			Path: "/custom_j",
			Method: map[string]Response{
				http.MethodGet: FuncResponse{
					Json: func(c CustomParam, _ *http.Request) interface{} {
						return fmt.Sprintf("custom_j %d", c.Count)
					},
				},
			},
		},
		PathConfig{
			Path: "/custom_h",
			Method: map[string]Response{
				http.MethodGet: FuncResponse{
					Handler: func(c CustomParam, w http.ResponseWriter, _ *http.Request) {
						io.WriteString(w, "handler func")
					},
				},
			},
		},
	})
	defer server.Close()

	check_get := func(path string, expected string) {
		if v := get(t, server.URL, path); v != expected {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expected, v)
		}
	}

	check_get("/text", "sample text")
	check_get("/json_t", "123")
	if v := get(t, server.URL, "/json_r"); v[0:1] != "{" {
		t.Errorf("Invalid json handler response /json_r: %s", v)
	}

	check_get("/linear", "text 1")
	check_get("/linear", "text 2")
	check_get("/linear", "text 3")
	check_get("/linear", "text 1")

	check_get("/custom_t", "custom_t 1")
	check_get("/custom_j", "\"custom_j 1\"\n")
	check_get("/custom_t", "custom_t 2")
	check_get("/custom_j", "\"custom_j 2\"\n")
	check_get("/custom_h", "handler func")
}

func Test_Builder(t *testing.T) {
	server := Start([]BuildablePathConfig{
		Path("/text").
			Get().
			Text("text 1").
			Text("text 2").Status(http.StatusForbidden),
		Path("/json").Get().Json(111),
		Path("/all_method").
			Get().Text("get").
			Post().Text("post").
			Delete().Text("delete").
			Put().Text("put"),
	})
	defer server.Close()

	check_get := func(path string, expected string) {
		if v := get(t, server.URL, path); v != expected {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expected, v)
		}
	}

	check_post := func(path string, body string, expected string) {
		if v := post(t, server.URL, path, "text/plain; charset=utf-8", body); v != expected {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expected, v)
		}
	}

	check_get("/text", "text 1")
	check_get("/text", "text 2")
	check_get("/json", "111")

	check_get("/all_method", "get")
	check_post("/all_method", "dummy", "post")
}
