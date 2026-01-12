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

// HandlerSet は、Handlerに情報を持たせる例。
// Handlerが何かしらデータに依存する場合は、Handlerをメソッドとして実装してMuxに渡すとよい。
type HandlerSet struct {
	common *Common
}

func okHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "OK")
}

func panicHandler(_ http.ResponseWriter, _ *http.Request) {
	panic("panic by panicHandler()")
}

func (s *HandlerSet) rootHandler(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "This is Root.")
	s.common.count++
}

func (s *HandlerSet) showCount(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, fmt.Sprintf("%d", s.common.count))
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

func NewHandlePanicMiddleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type CorsResult int

const (
	CorsResultOk CorsResult = iota
	CorsResultBad
	CorsResultNone
)

func newCorsChecker(allowedOrigins []string) func(string) CorsResult {
	allowedOriginSet := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		normalized := normalizeOrigin(o)
		if normalized == "" {
			panic(fmt.Sprintf("Invalid CORS origin: %s", o))
		}
		allowedOriginSet[normalized] = struct{}{}
	}

	return func(origin string) CorsResult {
		if origin == "" {
			return CorsResultNone
		}
		normalizedOrigin := normalizeOrigin(origin)
		if _, ok := allowedOriginSet[normalizedOrigin]; ok {
			return CorsResultOk
		} else {
			return CorsResultBad
		}
	}
}

func NewCorsMiddleware(next http.Handler, allowedOrigins []string) http.HandlerFunc {
	corsChecker := newCorsChecker(allowedOrigins)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		switch corsChecker(origin) {
		case CorsResultOk:
			log.Printf("CORS: origin accepted. (origin=%s)\n", origin)
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		case CorsResultBad:
			log.Printf("CORS: origin denied. (origin=%s)\n", origin)
		case CorsResultNone:
			// log.Printf("CORS: origin not specified\n")
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

func NewSecretHealthCheckHandlerFunc(secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sentSecret := r.URL.Query().Get("secret")
		if secret == sentSecret {
			_, _ = io.WriteString(w, "Healthy")
		} else {
			http.NotFound(w, r)
		}
	}
}

func CreateMux() *http.ServeMux {
	handlerSet := newHandlerSet(0)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handlerSet.rootHandler)
	mux.HandleFunc("/show", handlerSet.showCount)
	mux.HandleFunc("/healthcheck", NewSecretHealthCheckHandlerFunc("sample"))

	return mux
}
