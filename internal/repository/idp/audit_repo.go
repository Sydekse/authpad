package idp

import (
	"context"
	"encoding/json"
	"time"

	"github.com/auth-project/goauth/internal/database"
	"github.com/google/uuid"
)

// AuditRepo writes IdP audit logs.
type AuditRepo struct {
	db *database.IdPDB
}

func NewAuditRepo(db *database.IdPDB) *AuditRepo {
	return &AuditRepo{db: db}
}

func (r *AuditRepo) Log(ctx context.Context, userID *uuid.UUID, action string, details map[string]any) error {
	var detailsJSON []byte
	if details != nil {
		detailsJSON, _ = json.Marshal(details)
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO idp_audit_logs (id, user_id, action, details, created_at)
		VALUES ($1, $2, $3, COALESCE($4::jsonb, '{}'), $5)
	`, uuid.New(), userID, action, detailsJSON, time.Now())
	return err
}

func (r *AuditRepo) ListByUserID(ctx context.Context, userID uuid.UUID, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.Query(ctx, `
		SELECT action, details, created_at FROM idp_audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var action string
		var details []byte
		var createdAt time.Time
		if err := rows.Scan(&action, &details, &createdAt); err != nil {
			return nil, err
		}
		entry := map[string]any{"action": action, "created_at": createdAt, "source": "idp"}
		if len(details) > 0 {
			var d map[string]any
			_ = json.Unmarshal(details, &d)
			entry["details"] = d
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func (r *AuditRepo) ListRecent(ctx context.Context, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := r.db.Query(ctx, `
		SELECT user_id, action, details, created_at FROM idp_audit_logs ORDER BY created_at DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var userID *uuid.UUID
		var action string
		var details []byte
		var createdAt time.Time
		if err := rows.Scan(&userID, &action, &details, &createdAt); err != nil {
			return nil, err
		}
		entry := map[string]any{"action": action, "created_at": createdAt, "source": "idp"}
		if userID != nil {
			entry["user_id"] = userID.String()
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}
