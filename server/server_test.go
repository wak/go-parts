package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"testing"
)

func funcName(f any) string {
	v := reflect.ValueOf(f)
	pc := v.Pointer()
	return runtime.FuncForPC(pc).Name()
}

// ハンドラ単体でテストする
func Test_RootHandler(t *testing.T) {
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

// サーバを起動してハンドラ単体でテストする
func Test_Handlers(t *testing.T) {
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
		ts := httptest.NewServer(http.HandlerFunc(data.handlerFunc))
		defer ts.Close()
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
func Test_Routing(t *testing.T) {
	mux := CreateMux()

	dataSetv := []struct {
		path         string
		expectedBody string
	}{
		{"/", "This is Root."},
		{"/show", "1"},
		{"/", "This is Root."},
		{"/show", "2"},
	}

	for _, data := range dataSetv {
		req := httptest.NewRequest(http.MethodGet, data.path, nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK || rec.Body.String() != data.expectedBody {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	}
}
