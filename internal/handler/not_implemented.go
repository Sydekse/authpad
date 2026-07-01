package handler

import (
	"net/http"
)

// NotImplemented returns 501 for endpoints not yet implemented.
func NotImplemented(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":{"code":"NOT_IMPLEMENTED","message":"This endpoint is not yet implemented"}}`))
}
