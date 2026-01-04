package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/websocket"
)

type fakeReceiveErrorIO struct {
	xnetWSIO
}

func (f fakeReceiveErrorIO) Receive(ws *websocket.Conn, v any) error {
	return errors.New("failed")
}

type fakeSendErrorIO struct {
	xnetWSIO
}

func (f fakeSendErrorIO) Send(ws *websocket.Conn, v any) error {
	return errors.New("failed")
}

func Test_WebSocket_Origin(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/ws", NewWsEchoHttpHandler([]string{"http://example.co.jp:8080"}))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	testDataSet := []struct {
		origin         string
		connectSuccess bool
	}{
		{"http://example.co.jp:8080", true},
		{"http://example.co.jp", false},
		{"http://example.com:8080", false},
		// {"", false}, // Originを空にしてリクエストは出せない(クライアント側でエラー)
	}
	for _, data := range testDataSet {
		ws, err := websocket.Dial(wsURL, "", data.origin)

		if data.connectSuccess {
			if err != nil {
				t.Fatalf("Dial failed: %v", err)
				continue
			}
		} else {
			if err == nil {
				t.Errorf("Dial must failed but connected: origin=%s", data.origin)
				continue
			}
			continue
		}
		t.Cleanup(func() { _ = ws.Close() })

		if err := websocket.Message.Send(ws, "hello"); err != nil {
			t.Fatalf("Send websocket message failed: %v", err)
		}

		var got string
		if err := websocket.Message.Receive(ws, &got); err != nil {
			t.Fatalf("Receive websocket message failed: %v", err)
		}

		if got != "hello" {
			t.Fatalf("Received websocket message error: %s", got)
		}
	}
}

func Test_WebSocket_Echo(t *testing.T) {
	mux := http.NewServeMux()
	h := newWsEchoWebSocketHandler(xnetWSIO{})
	mux.Handle("/ws", websocket.Handler(h))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	ws, err := websocket.Dial(wsURL, "", ts.URL)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	for range 10 {
		if err := websocket.Message.Send(ws, "hello"); err != nil {
			t.Fatalf("Send websocket message failed: %v", err)
		}

		var got string
		if err := websocket.Message.Receive(ws, &got); err != nil {
			t.Fatalf("Receive websocket message failed: %v", err)
		}

		if got != "hello" {
			t.Fatalf("Received websocket message error: %s", got)
		}
	}
}

func Test_WebSocket_Echo_SendError(t *testing.T) {
	mux := http.NewServeMux()
	h := newWsEchoWebSocketHandler(fakeReceiveErrorIO{})
	mux.Handle("/ws", websocket.Handler(h))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	ws, err := websocket.Dial(wsURL, "", ts.URL)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	if err := websocket.Message.Send(ws, "hello"); err != nil {
		t.Errorf("Send websocket message failed: %v", err)
	}

	var got string
	err = websocket.Message.Receive(ws, &got)
	if err == nil {
		t.Errorf("Receive() should returns error")
	}
}

func Test_WebSocket_Echo_ReceiveError(t *testing.T) {
	mux := http.NewServeMux()
	h := newWsEchoWebSocketHandler(fakeSendErrorIO{})
	mux.Handle("/ws", websocket.Handler(h))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	ws, err := websocket.Dial(wsURL, "", ts.URL)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	if err := websocket.Message.Send(ws, "hello"); err != nil {
		// WS側はエラーになるが、クライアント側は送信できる。
		t.Errorf("Send websocket message failed: %v", err)
	}

	var got string
	err = websocket.Message.Receive(ws, &got)
	if err == nil {
		t.Errorf("Receive() should returns error")
	}
}
