package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func Test_GreetingStreamHandler(t *testing.T) {
	funcName := funcName(greetingStreamHandler)
	w := httptest.NewRecorder()

	writeGreetingStream(w, w, func(time.Duration) {})
	res := w.Result()
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode != http.StatusOK {
		t.Errorf("Handler %s response code != 200 (%d)", funcName, res.StatusCode)
	}
	if string(body) != "Hello.\nThis is streaming handler.\n" {
		t.Errorf("Handler %s response body invalid. (body = %s)", funcName, string(body))
	}
}
