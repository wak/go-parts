package httpmock

import (
	"fmt"
	"io"
	"net/http"
	"testing"
)

func Test_ServerRun(t *testing.T) {
	server := Start([]PathConfig{
		{
			Path:      "/text",
			GetMethod: []Response{TextResponse{Text: "sample text"}},
		},
		{
			Path: "/json_r",
			GetMethod: JsonResponse{Raw: map[string]interface{}{
				"path":  "/json",
				"value": "json raw",
			}},
		},
		{
			Path:      "/json_t",
			GetMethod: JsonResponse{Text: "123"},
		},
		{
			Path: "/linear",
			GetMethod: LinearResponse{
				Responses: []Response{
					TextResponse{Text: "text 1"},
					TextResponse{Text: "text 2"},
					TextResponse{Text: "text 3"},
				},
			},
		},
		{
			Path: "/custom_t",
			GetMethod: FuncResponse{Text: func(c CustomParam, _ *http.Request) string {
				return fmt.Sprintf("custom_t %d", c.Count)
			}},
		},
		{
			Path: "/custom_j",
			GetMethod: FuncResponse{Json: func(c CustomParam, _ *http.Request) interface{} {
				return fmt.Sprintf("custom_j %d", c.Count)
			}},
		},
		{
			Path: "/custom_h",
			GetMethod: FuncResponse{Handler: func(c CustomParam, w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, "handler func")
			}},
		},
	})
	defer server.Close()

	get := func(path string) string {
		res, err := http.Get(server.URL + path)
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

	check_get := func(path string, expected string) {
		if v := get(path); v != expected {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expected, v)
		}
	}

	check_get("/text", "sample text")
	check_get("/json_t", "123")
	if v := get("/json_r"); v[0:1] != "{" {
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
