package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/auth-project/goauth/internal/database"
	"github.com/google/uuid"
)

// AuditRepo writes auth audit logs.
type AuditRepo struct {
	db *database.AuthDB
}

func NewAuditRepo(db *database.AuthDB) *AuditRepo {
	return &AuditRepo{db: db}
}

func (r *AuditRepo) Log(ctx context.Context, userID *uuid.UUID, action, ip, ua string, details map[string]any) error {
	var detailsJSON []byte
	if details != nil {
		detailsJSON, _ = json.Marshal(details)
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO auth_audit_logs (id, user_id, action, ip_address, user_agent, details, created_at)
		VALUES ($1, $2, $3, NULLIF($4, '')::inet, $5, COALESCE($6::jsonb, '{}'), $7)
	`, uuid.New(), userID, action, ip, ua, detailsJSON, time.Now())
	return err
}

func (r *AuditRepo) ListByUserID(ctx context.Context, userID uuid.UUID, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.Query(ctx, `
		SELECT action, ip_address::text, user_agent, details, created_at
		FROM auth_audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var action, ip, ua string
		var details []byte
		var createdAt time.Time
		if err := rows.Scan(&action, &ip, &ua, &details, &createdAt); err != nil {
			return nil, err
		}
		entry := map[string]any{"action": action, "created_at": createdAt, "source": "auth"}
		if ip != "" {
			entry["ip_address"] = ip
		}
		if ua != "" {
			entry["user_agent"] = ua
		}
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
		SELECT user_id, action, details, created_at FROM auth_audit_logs ORDER BY created_at DESC LIMIT $1
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
		entry := map[string]any{"action": action, "created_at": createdAt, "source": "auth"}
		if userID != nil {
			entry["user_id"] = userID.String()
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}
