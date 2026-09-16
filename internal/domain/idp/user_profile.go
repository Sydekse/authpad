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
	ID       uuid.UUID  `json:"id"`
	UserID   uuid.UUID  `json:"user_id"`
	GroupID  uuid.UUID  `json:"group_id"`
	JoinedAt time.Time  `json:"joined_at"`
	AddedBy  *uuid.UUID `json:"added_by,omitempty"`
}

type Invitation struct {
	ID             uuid.UUID       `json:"id"`
	Email          string          `json:"email"`
	Role           string          `json:"role,omitempty"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	TokenHash      string          `json:"-"`
	ExpiresAt      time.Time       `json:"expires_at"`
	InvitedBy      *uuid.UUID      `json:"invited_by,omitempty"`
	RedeemedAt     *time.Time      `json:"redeemed_at,omitempty"`
	RedeemedUserID *uuid.UUID      `json:"redeemed_user_id,omitempty"`
	RevokedAt      *time.Time      `json:"revoked_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type Organization struct {
	ID        uuid.UUID       `json:"id"`
	Slug      string          `json:"slug"`
	Name      string          `json:"name"`
	ImageURL  string          `json:"image_url,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedBy *uuid.UUID      `json:"created_by,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type OrganizationMembership struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	UserID         uuid.UUID  `json:"user_id"`
	Role           string     `json:"role"`
	Status         string     `json:"status"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`
	LevelID        *uuid.UUID `json:"level_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

type OrganizationInvitation struct {
	ID             uuid.UUID       `json:"id"`
	OrganizationID uuid.UUID       `json:"organization_id"`
	Email          string          `json:"email"`
	Role           string          `json:"role"`
	TokenHash      string          `json:"-"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	ExpiresAt      time.Time       `json:"expires_at"`
	InvitedBy      *uuid.UUID      `json:"invited_by,omitempty"`
	AcceptedAt     *time.Time      `json:"accepted_at,omitempty"`
	RevokedAt      *time.Time      `json:"revoked_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type OrganizationRole struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type OrganizationDepartment struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"created_at"`
}

type OrganizationLevel struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"created_at"`
}
