package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

type Common struct {
	count int
}

// Handlerが何かしらデータに依存する場合は、
// HandlerをメソッドとしてMuxに渡すとよい。
type HandlerSet struct {
	common *Common
}

func okHandler(w http.ResponseWriter, _ *http.Request) {
	io.WriteString(w, "OK")
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

func newCountMiddleware(next http.Handler) (http.HandlerFunc, *int) {
	count := 0 // Mutexが必要
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count += 1
		next.ServeHTTP(w, r)
	}), &count
}

func NewCorsMiddleware(next http.Handler, allowedOrigins []string) http.HandlerFunc {
	allowedOriginSet := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		normalized := normalizeOrigin(o)
		if normalized == "" {
			panic(fmt.Sprintf("Invalid CORS origin: %s", o))
		}
		allowedOriginSet[normalized] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			normalizedOrigin := normalizeOrigin(origin)
			if _, ok := allowedOriginSet[normalizedOrigin]; ok {
				log.Println("CORS: origin accepted.")
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			} else {
				log.Printf("CORS: origin denied. (origin=%s)\n", origin)
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func normalizeOrigin(origin string) string {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return ""
		}
	}
	return u.Scheme + "://" + host + ":" + port
}

func CreateMux() *http.ServeMux {
	handlerSet := newHandlerSet(0)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handlerSet.rootHandler)
	mux.HandleFunc("/show", handlerSet.showCount)

	return mux
}
