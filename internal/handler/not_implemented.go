package handler

import (
	"net/http"

	"github.com/Sydekse/authpad/pkg/apierror"
)

// NotImplemented returns 501 for endpoints not yet implemented.
func NotImplemented(w http.ResponseWriter, r *http.Request) {
	apierror.WriteJSON(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "This endpoint is not yet implemented")
}
