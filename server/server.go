package server

import (
	"fmt"
	"io"
	"net/http"
)

type Common struct {
	count int
}

// Handlerが何かしらデータに依存する場合は、
// HandlerをメソッドとしてMuxに渡すとよい。
type HandlerSet struct {
	common *Common
}

func (s *HandlerSet) rootHandler(w http.ResponseWriter, _ *http.Request) {
	io.WriteString(w, "This is Root.")
	s.common.count++
}

func (s *HandlerSet) showCount(w http.ResponseWriter, _ *http.Request) {
	io.WriteString(w, fmt.Sprintf("%d", s.common.count))
}

func newHandlerSet(initalCount int) *HandlerSet {
	common := Common{initalCount}
	handlerSet := HandlerSet{&common}

	return &handlerSet
}

func CreateMux() *http.ServeMux {
	handlerSet := newHandlerSet(0)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handlerSet.rootHandler)
	mux.HandleFunc("/show", handlerSet.showCount)

	return mux
}
