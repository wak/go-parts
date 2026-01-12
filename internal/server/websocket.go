package server

import (
	"errors"
	"io"
	"log"
	"net/http"

	"golang.org/x/net/websocket"
)

type wsIO interface {
	Receive(*websocket.Conn, any) error
	Send(*websocket.Conn, any) error
}

type xnetWSIO struct{}

func (xnetWSIO) Receive(ws *websocket.Conn, v any) error {
	return websocket.Message.Receive(ws, v)
}
func (xnetWSIO) Send(ws *websocket.Conn, v any) error {
	return websocket.Message.Send(ws, v)
}

func NewWsHttpHandler(handler websocket.Handler, allowedOrigins []string) http.Handler {
	corsChecker := newCorsChecker(allowedOrigins)
	return websocket.Server{
		Handler: handler,
		Handshake: func(config *websocket.Config, req *http.Request) error {
			origin := req.Header.Get("Origin")
			switch corsChecker(origin) {
			case CorsResultOk:
				log.Printf("CORS WS: origin accepted. (origin=%s)\n", origin)
				return nil
			case CorsResultBad:
				log.Printf("CORS WS: origin denied. (origin=%s)\n", origin)
				return errors.New("invalid origin")
			case CorsResultNone:
				log.Printf("CORS WS: origin not specified\n")
				return errors.New("no origin")
			}
			panic("no here")
		},
	}
}

func NewWsEchoHttpHandler(allowedOrigins []string) http.Handler {
	return NewWsHttpHandler(newWsEchoWebSocketHandler(xnetWSIO{}), allowedOrigins)
}

func newWsEchoWebSocketHandler(inout wsIO) websocket.Handler {
	return func(ws *websocket.Conn) {
		defer func() { _ = ws.Close() }()
		log.Println("WebSocket echo handler start.")

		for {
			var msg string
			err := inout.Receive(ws, &msg)
			if err != nil {
				if err == io.EOF {
					// クライアントが切断した
					log.Println("client closed")
					return
				}
				// その他のエラー
				log.Printf("receive error: %s", err)
				return
			}

			if err := inout.Send(ws, msg); err != nil {
				log.Println("send error:", err)
				return
			}
		}
	}
}
