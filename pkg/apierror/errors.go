package apierror

import (
	"encoding/json"
	"net/http"
	"net/url"
)

type Error struct {
	Error struct {
		Code     string `json:"code"`
		Message  string `json:"message"`
		Redirect string `json:"redirect,omitempty"`
	} `json:"error"`
}

func WriteJSON(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Error{
		Error: struct {
			Code     string `json:"code"`
			Message  string `json:"message"`
			Redirect string `json:"redirect,omitempty"`
		}{Code: code, Message: message},
	})
}

func UnauthorizedWithRedirect(w http.ResponseWriter, signInURL, returnTo, code, message string) {
	redirect := signInURL
	if signInURL != "" && returnTo != "" {
		redirect = signInURL
		if signInURL != "" {
			sep := "?"
			if containsQuery(signInURL) {
				sep = "&"
			}
			redirect = signInURL + sep + "return_to=" + urlEncode(returnTo)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(Error{
		Error: struct {
			Code     string `json:"code"`
			Message  string `json:"message"`
			Redirect string `json:"redirect,omitempty"`
		}{Code: code, Message: message, Redirect: redirect},
	})
}

func containsQuery(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '?' {
			return true
		}
	}
	return false
}

func urlEncode(s string) string {
	return url.QueryEscape(s)
}

func BadRequest(w http.ResponseWriter, code, message string) {
	WriteJSON(w, http.StatusBadRequest, code, message)
}

func Unauthorized(w http.ResponseWriter, code, message string) {
	WriteJSON(w, http.StatusUnauthorized, code, message)
}

func Forbidden(w http.ResponseWriter, code, message string) {
	WriteJSON(w, http.StatusForbidden, code, message)
}

func NotFound(w http.ResponseWriter, code, message string) {
	WriteJSON(w, http.StatusNotFound, code, message)
}

func Conflict(w http.ResponseWriter, code, message string) {
	WriteJSON(w, http.StatusConflict, code, message)
}

func Internal(w http.ResponseWriter, code, message string) {
	WriteJSON(w, http.StatusInternalServerError, code, message)
}
