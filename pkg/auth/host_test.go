package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteHostErrorIsJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeHostError(rec, http.StatusUnauthorized, "NO_SESSION", "Authentication required")

	if got := rec.Code; got != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if body.Error.Code != "NO_SESSION" {
		t.Fatalf("error.code = %q, want NO_SESSION", body.Error.Code)
	}
}
