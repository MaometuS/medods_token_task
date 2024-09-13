package use_case

import (
	"context"
	"github.com/maometus/medods_token_task/src/entity/models"
)

type Repository interface {
	GenerateJWT(claims map[string]any) (string, error)
	GetJWTClaims(token string) (map[string]any, error)
	CreateToken(ctx context.Context, token *models.RefreshToken) error
	UpdateToken(ctx context.Context, token *models.RefreshToken) error
	GetToken(ctx context.Context, tokenID string) (*models.RefreshToken, error)
	SendMail(address string, text string) error
}
