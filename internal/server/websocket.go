package server

import (
	"io"
	"log"

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

func newWsEchoHandler() func(*websocket.Conn) {
	return newWsEchoHandlerRaw(xnetWSIO{})
}

func newWsEchoHandlerRaw(inout wsIO) func(*websocket.Conn) {
	return func(ws *websocket.Conn) {
		defer ws.Close()

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
