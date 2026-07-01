package apptypes

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
)

var namePattern = regexp.MustCompile(`^[\p{L}\p{N}\s._-]{1,255}$`)

func (s ProfileSchema) ValidateProfile(raw map[string]any) (ProfileInput, error) {
	out := ProfileInput{Metadata: map[string]any{}}
	if raw == nil {
		raw = map[string]any{}
	}
	name, ok := raw["name"].(string)
	if !ok || strings.TrimSpace(name) == "" {
		return out, fmt.Errorf("name is required")
	}
	name = strings.TrimSpace(name)
	if !namePattern.MatchString(name) {
		return out, fmt.Errorf("name contains invalid characters")
	}
	out.Name = name

	if v, ok := raw["image_url"]; ok {
		if s, ok := v.(string); ok {
			out.ImageURL = strings.TrimSpace(s)
			if out.ImageURL != "" {
				if _, err := url.ParseRequestURI(out.ImageURL); err != nil {
					return out, fmt.Errorf("image_url must be a valid URL")
				}
			}
		}
	}
	if v, ok := raw["bio"]; ok {
		if s, ok := v.(string); ok {
			out.Bio = strings.TrimSpace(s)
		}
	}

	reserved := map[string]struct{}{"name": {}, "image_url": {}, "bio": {}}
	for _, field := range s.Fields {
		val, present := raw[field.Name]
		if !present || val == nil {
			if field.Required {
				return out, fmt.Errorf("%s is required", field.Name)
			}
			continue
		}
		if err := validateField(field, val); err != nil {
			return out, err
		}
		out.Metadata[field.Name] = val
	}
	for key := range raw {
		if _, ok := reserved[key]; ok {
			continue
		}
		found := false
		for _, field := range s.Fields {
			if field.Name == key {
				found = true
				break
			}
		}
		if !found {
			return out, fmt.Errorf("unknown profile field: %s", key)
		}
	}
	return out, nil
}

func validateField(field ProfileField, val any) error {
	if field.Validate != nil {
		if err := field.Validate(val); err != nil {
			return err
		}
	}
	switch field.Type {
	case FieldTypeString:
		if _, ok := val.(string); !ok {
			return fmt.Errorf("%s must be a string", field.Name)
		}
	case FieldTypeEmail:
		s, ok := val.(string)
		if !ok {
			return fmt.Errorf("%s must be an email string", field.Name)
		}
		if _, err := mail.ParseAddress(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("%s must be a valid email", field.Name)
		}
	case FieldTypeURL:
		s, ok := val.(string)
		if !ok {
			return fmt.Errorf("%s must be a URL string", field.Name)
		}
		if _, err := url.ParseRequestURI(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("%s must be a valid URL", field.Name)
		}
	case FieldTypeInt:
		switch val.(type) {
		case float64, int, int64, json.Number:
		default:
			return fmt.Errorf("%s must be a number", field.Name)
		}
	case FieldTypeBool:
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("%s must be a boolean", field.Name)
		}
	}
	return nil
}
