package idp

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// UserProfile is the IdP-side profile (IdP DB).
type UserProfile struct {
	UserID    uuid.UUID       `json:"user_id"`
	Name      string          `json:"name"`
	ImageURL  string          `json:"image_url,omitempty"`
	Bio       string          `json:"bio,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// Role is a predefined role (IdP DB).
type Role struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Group is a group (class, school, etc.) (IdP DB).
type Group struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	GroupType   string          `json:"group_type,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

// UserRole links a user to a role (IdP DB).
type UserRole struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	RoleID     uuid.UUID  `json:"role_id"`
	AssignedAt time.Time  `json:"assigned_at"`
	AssignedBy *uuid.UUID `json:"assigned_by,omitempty"`
}

// UserGroup links a user to a group (IdP DB).
type UserGroup struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	GroupID   uuid.UUID  `json:"group_id"`
	JoinedAt  time.Time  `json:"joined_at"`
	AddedBy   *uuid.UUID `json:"added_by,omitempty"`
}
