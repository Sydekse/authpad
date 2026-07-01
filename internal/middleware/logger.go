package middleware

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// Logger logs HTTP requests with method, path, status, and duration.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := r.Context().Value(RequestIDKey)
		ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(ww, r)

		entry := log.With().
			Str("request_id", fmtString(requestID)).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote", r.RemoteAddr).
			Int("status", ww.status).
			Dur("duration_ms", time.Since(start)).
			Logger()

		// Skip 404 at Info to reduce noise from GET /, /robots.txt, bots, etc.
		if ww.status == http.StatusNotFound {
			entry.Debug().Msg("request")
		} else {
			entry.Info().Msg("request")
		}
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func fmtString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
