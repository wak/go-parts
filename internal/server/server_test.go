package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"testing"
)

func funcName(f any) string {
	v := reflect.ValueOf(f)
	pc := v.Pointer()
	return runtime.FuncForPC(pc).Name()
}

func Test_CorsMiddleware(t *testing.T) {
	handler := NewCorsMiddleware(
		http.HandlerFunc(okHandler),
		[]string{"http://example.jp"},
	)

	testDataSet := []struct {
		method        string
		origin        string
		shouldSuccess bool
	}{
		{http.MethodOptions, "", false},
		{http.MethodGet, "http://example.net", false},
		{http.MethodGet, "http://example.jp", true},
		{http.MethodGet, "http://example.jp:80", true},
		{http.MethodGet, "http://example.jp:8080", false},
	}
	for _, data := range testDataSet {
		req := httptest.NewRequest(data.method, "/", nil)
		req.Header.Set("Origin", data.origin)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		res := w.Result()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Handler response code != 200 (%d)", res.StatusCode)
		}
		acao := res.Header.Get("Access-Control-Allow-Origin")
		if data.shouldSuccess {
			if acao != data.origin {
				t.Errorf("CORS for %s should succeed. (ACAO=%s)", data.origin, acao)
			}
		} else {
			if acao != "" {
				t.Errorf("CORS for %s should failed. (ACAO=%s)", data.origin, acao)
			}
		}
	}
}

func Test_CorsMiddlewareWithInvalidConfig(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic, but did not panic")
		}
	}()

	// panic
	NewCorsMiddleware(
		http.NotFoundHandler(),
		[]string{"http://"},
	)
}

func Test_normalizeOrigin(t *testing.T) {
	testDataSet := []struct {
		origin     string
		normalized string
	}{
		{"", ""},
		{"ftp://localhost", ""},
		{"http://example.jp", "http://example.jp:80"},
		{"http://example.jp:80", "http://example.jp:80"},
		{"https://example.jp", "https://example.jp:443"},
		{"https://example.jp:443", "https://example.jp:443"},
		{"https://example.jp:8080", "https://example.jp:8080"},
	}
	for _, data := range testDataSet {
		normalized := normalizeOrigin(data.origin)
		if normalized != data.normalized {
			t.Errorf("Normalize %s should be %s, but %s.", data.origin, data.normalized, normalized)
		}
	}
}

// ハンドラ単体でテストする
func Test_Handler(t *testing.T) {
	handlerSet := newHandlerSet(100)

	testDataSet := []struct {
		handlerFunc  http.HandlerFunc
		expectedBody string
	}{
		{handlerSet.rootHandler, "This is Root."},
		{handlerSet.showCount, "101"},
	}

	for _, data := range testDataSet {
		funcName := funcName(data.handlerFunc)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()

		data.handlerFunc(w, req)
		res := w.Result()
		responseBody, _ := io.ReadAll(res.Body)

		if res.StatusCode != http.StatusOK {
			t.Errorf("Handler %s response code != 200 (%d)", funcName, res.StatusCode)
		}
		if string(responseBody) != data.expectedBody {
			t.Errorf("Handler %s response body invalid. (body = %s)", funcName, responseBody)
		}
	}
}

// ルーティングありのテストをする
func Test_Routing(t *testing.T) {
	mux := CreateMux()

	testDataSet := []struct {
		path         string
		expectedBody string
	}{
		{"/", "This is Root."},
		{"/show", "1"},
		{"/", "This is Root."},
		{"/show", "2"},
	}

	for _, data := range testDataSet {
		req := httptest.NewRequest(http.MethodGet, data.path, nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK || rec.Body.String() != data.expectedBody {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	}
}

// ミドルウェアのテストをする
func Test_Middleware(t *testing.T) {
	mux, count := newCountMiddleware(CreateMux())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	if *count != 0 {
		t.Fatalf("count error = %d", *count)
	}

	mux.ServeHTTP(rec, req)
	mux.ServeHTTP(rec, req)

	if *count != 2 {
		t.Fatalf("count error = %d", *count)
	}
}

// サーバを起動してハンドラ単体でテストする
func Test_HandlerWithServer(t *testing.T) {
	handlerSet := newHandlerSet(100)

	testDataSet := []struct {
		handlerFunc  http.HandlerFunc
		expectedBody string
	}{
		{handlerSet.rootHandler, "This is Root."},
		{handlerSet.showCount, "101"},
	}

	for _, data := range testDataSet {
		ts := httptest.NewServer(http.HandlerFunc(data.handlerFunc))
		defer ts.Close()

		funcName := funcName(data.handlerFunc)
		res, err := http.Get(ts.URL)
		if err != nil {
			t.Errorf("Failed GET to %s", funcName)
		}
		responseBody, err := io.ReadAll(res.Body)
		if err != nil {
			t.Errorf("Failed to read response of %s", funcName)
		}

		res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Handler %s response code != 200 (%d)", funcName, res.StatusCode)
		}
		if string(responseBody) != data.expectedBody {
			t.Errorf("Handler %s response body invalid. (body = %s)", funcName, responseBody)
		}

		ts.Close()
	}
}

// サーバを起動してルーティングありのテストをする
func Test_RoutingWithServer(t *testing.T) {
	mux := CreateMux()

	testDataSet := []struct {
		path         string
		expectedBody string
	}{
		{"/", "This is Root."},
		{"/show", "1"},
		{"/", "This is Root."},
		{"/show", "2"},
	}

	handler, count := newCountMiddleware(mux)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	for _, data := range testDataSet {
		u, _ := url.Parse(ts.URL)
		u.Path = data.path

		res, err := http.Get(u.String())
		if err != nil {
			t.Errorf("Failed GET to %s", data.path)
		}

		responseBody, err := io.ReadAll(res.Body)
		if err != nil {
			t.Errorf("Failed to read response of %s", data.path)
		}

		res.Body.Close()

		if res.StatusCode != http.StatusOK || string(responseBody) != data.expectedBody {
			t.Fatalf("status = %d, body = %s (expect %s)", res.StatusCode, string(responseBody), data.expectedBody)
		}
	}
	if *count != 4 {
		t.Fatalf("count error = %d", *count)
	}
}
