package handler

import (
	"net/http"
)

// Health returns 200 OK for liveness probes.
func Health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
