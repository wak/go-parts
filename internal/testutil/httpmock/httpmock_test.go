package httpmock

import (
	"errors"
	"fmt"
	"go-parts/internal/testutil"
	"io"
	"net/http"
	"os"
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
	testutil.MustSuccess(t, res.Body.Close())
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

func Test_helper(t *testing.T) {
	server := Start([]BuildablePathConfig{
		Path("/text").Text("sample text"),
		Path("/json_r").Json(map[string]interface{}{
			"path":  "/json",
			"value": "json raw",
		}),
		Path("/json_t").JsonS("123"),
		Path("/xml").Xml("<t></t>"),
		Path("/linear").
			Text("text 1").
			Text("text 2").
			Text("text 3"),
		Path("/handler_1").
			Handler(func(c CustomParam, w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, fmt.Sprintf("handler_1 %d", c.Count))
			}),
		Path("/handler_2").
			Handler(func(c CustomParam, w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, fmt.Sprintf("handler_2 %d", c.Count))
			}),
	})
	defer server.Close()

	check_get := func(path string, expected string, contentType string) {
		_, header, body := get(t, server.URL, path)
		if body != expected {
			t.Errorf("Invalid handler (%s) response. expected: %q but actual: %q", path, expected, body)
		}
		if !strings.HasPrefix(header.Get("Content-Type"), contentType) {
			t.Errorf("Invalid handler (%s) Content-Type response. expected: %q but actual: %q", path, header.Get("Content-Type"), contentType)
		}
	}

	check_get("/text", "sample text", "text/plain")
	check_get("/json_t", "123", "application/json")
	if _, header, v := get(t, server.URL, "/json_r"); !strings.HasPrefix(v, "{") || !strings.HasPrefix(header.Get("Content-Type"), "application/json") {
		t.Errorf("Invalid json handler response /json_r: %s, %s", v, header.Get("Content-Type"))
	}
	check_get("/xml", "<t></t>", "application/xml")

	check_get("/linear", "text 1", "text/plain")
	check_get("/linear", "text 2", "text/plain")
	check_get("/linear", "text 3", "text/plain")
	check_get("/linear", "text 1", "text/plain")

	check_get("/handler_1", "handler_1 1", "")
	check_get("/handler_2", "handler_2 1", "")
	check_get("/handler_1", "handler_1 2", "")
	check_get("/handler_2", "handler_2 2", "")
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

func Test_F_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic but did not panic")
		}
	}()

	_ = F("this-file-should-not-exist.txt")
}

func Test_projectRoot_panic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic but did not panic")
		}
		if r != "Cannot detect project root." {
			t.Fatal("not targetted panic")
		}
	}()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	projectRoot(os.Getwd)
}

func Test_projectRoot_panic_getwd(t *testing.T) {
	err := errors.New("failed")
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic but did not panic")
		}
		if r != err {
			t.Fatal("not targetted panic")
		}
	}()
	projectRoot(func() (string, error) { return "", err })
}
func Test_F(t *testing.T) {
	text := F("go.mod")
	if !strings.HasPrefix(text, "module") {
		t.Errorf("invalid heading: %s", text[0:7])
	}
}

func Test_start_panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic but did not panic")
		}
	}()

	server := Start([]BuildablePathConfig{
		Path("/json").Json(func() {}),
	})
	defer server.Close()

	get(t, server.URL, "/json")
}

func Test_panic_method_not_defined(t *testing.T) {
	server := Start([]BuildablePathConfig{
		Path("/").Get().Text("get"),
	})
	defer server.Close()

	code, _, body := del(t, server.URL, "/")
	if !strings.HasPrefix(body, "Method DELETE for /") ||
		code != 599 {
		t.Errorf("response is invalid: %d, %s", code, body)
	}
}
