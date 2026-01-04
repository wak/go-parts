package httpmock

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func request(t *testing.T, method string, url string, path string, body string) (int, http.Header, string) {
	req, err := http.NewRequest(method, url+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to create %s request %s: %v", method, path, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed %s %s: %v", method, path, err)
	}

	responseBody, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatalf("Failed to read response of %s: %v", path, err)
	}
	return res.StatusCode, res.Header, string(responseBody)
}

func get(t *testing.T, url string, path string) (int, http.Header, string) {
	return request(t, http.MethodGet, url, path, "")
}

func post(t *testing.T, url string, path string, body string) (int, http.Header, string) {
	return request(t, http.MethodPost, url, path, body)
}

func put(t *testing.T, url string, path string, body string) (int, http.Header, string) {
	return request(t, http.MethodPut, url, path, body)
}

func del(t *testing.T, url string, path string) (int, http.Header, string) {
	return request(t, http.MethodDelete, url, path, "")
}

func Test_ServerRun(t *testing.T) {
	server := Start([]BuildablePathConfig{
		Path("/text").Get().Text("sample text"),
		Path("/json_r").Get().Json(map[string]interface{}{
			"path":  "/json",
			"value": "json raw",
		}),
		Path("/json_t").Get().JsonS("123"),
		Path("/linear").Get().
			Text("text 1").
			Text("text 2").
			Text("text 3"),
		Path("/handler_1").Get().
			Handler(func(c CustomParam, w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, fmt.Sprintf("handler_1 %d", c.Count))
			}),
		Path("/handler_2").Get().
			Handler(func(c CustomParam, w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, fmt.Sprintf("handler_2 %d", c.Count))
			}),
	})
	defer server.Close()

	check_get := func(path string, expected string) {
		if _, _, v := get(t, server.URL, path); v != expected {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expected, v)
		}
	}

	check_get("/text", "sample text")
	check_get("/json_t", "123")
	if _, _, v := get(t, server.URL, "/json_r"); v[0:1] != "{" {
		t.Errorf("Invalid json handler response /json_r: %s", v)
	}

	check_get("/linear", "text 1")
	check_get("/linear", "text 2")
	check_get("/linear", "text 3")
	check_get("/linear", "text 1")

	check_get("/handler_1", "handler_1 1")
	check_get("/handler_2", "handler_2 1")
	check_get("/handler_1", "handler_1 2")
	check_get("/handler_2", "handler_2 2")
}

func Test_Attributes(t *testing.T) {
	server := Start([]BuildablePathConfig{
		Path("/text").
			Get().
			Text("text 1").
			Status(http.StatusForbidden).
			ContentType("sampletype"),
	})
	defer server.Close()

	check_get := func(path string, expectedCode int, expectedContentType string, expectedBody string) {
		code, header, body := get(t, server.URL, path)
		if body != expectedBody {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expectedBody, body)
		}
		if code != expectedCode {
			t.Errorf("Invalid handler (%s) response. expected: %d but actual: %d", path, expectedCode, code)
		}
		if header.Get("Content-Type") != expectedContentType {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expectedContentType, header.Get("Content-Type"))
		}
	}

	check_get("/text", http.StatusForbidden, "sampletype", "text 1")
}

func Test_AllMethods(t *testing.T) {
	server := Start([]BuildablePathConfig{
		Path("/").
			Get().Text("get").
			Post().Text("post").
			Delete().Text("delete").
			Put().Text("put"),
	})
	defer server.Close()

	check_get := func(path string, expected string) {
		if _, _, v := get(t, server.URL, path); v != expected {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expected, v)
		}
	}

	check_post := func(path string, body string, expected string) {
		if _, _, v := post(t, server.URL, path, body); v != expected {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expected, v)
		}
	}

	check_put := func(path string, body string, expected string) {
		if _, _, v := put(t, server.URL, path, body); v != expected {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expected, v)
		}
	}

	check_del := func(path string, expected string) {
		if _, _, v := del(t, server.URL, path); v != expected {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expected, v)
		}
	}
	check_get("/", "get")
	check_post("/", "dummy", "post")
	check_del("/", "delete")
	check_put("/", "dummy", "put")
}
