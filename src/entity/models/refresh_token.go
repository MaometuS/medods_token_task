package models

import "time"

type RefreshToken struct {
	ID        int64
	Token     string
	TokenID   string
	Valid     bool
	CreatedAt time.Time
	UpdatedAt time.Time
}
