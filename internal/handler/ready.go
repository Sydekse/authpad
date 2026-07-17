package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/auth-project/authpad/internal/database"
)

// Ready returns a handler that checks Auth DB and IdP DB connectivity for readiness.
// If either pool is nil (not configured), readiness is false.
func Ready(authDB *database.AuthDB, idpDB *database.IdPDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authDB == nil || idpDB == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"ready":false,"reason":"database_not_configured"}`))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := authDB.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"ready":false,"reason":"auth_db_unavailable"}`))
			return
		}

		if err := idpDB.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"ready":false,"reason":"idp_db_unavailable"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ready":true}`))
	}
}
