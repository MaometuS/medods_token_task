package use_case

import (
	"context"
	"github.com/maometus/medods_token_task/src/entity/models"
	"github.com/stretchr/testify/mock"
)

type Repository interface {
	GenerateJWT(claims map[string]any) (string, error)
	GetJWTClaims(token string) (map[string]any, error)
	CreateToken(ctx context.Context, token *models.RefreshToken) error
	UpdateToken(ctx context.Context, token *models.RefreshToken) error
	GetToken(ctx context.Context, tokenID string) (*models.RefreshToken, error)
	SendMail(address string, text string) error
}

type RepositoryMock struct {
	mock.Mock
}

func (r *RepositoryMock) GenerateJWT(claims map[string]any) (string, error) {
	args := r.Called(claims)
	return args.String(0), args.Error(1)
}

func (r *RepositoryMock) GetJWTClaims(token string) (map[string]any, error) {
	args := r.Called(token)
	return args.Get(0).(map[string]any), args.Error(1)
}

func (r *RepositoryMock) CreateToken(ctx context.Context, token *models.RefreshToken) error {
	args := r.Called(ctx, token)
	return args.Error(0)
}

func (r *RepositoryMock) UpdateToken(ctx context.Context, token *models.RefreshToken) error {
	args := r.Called(ctx, token)
	return args.Error(0)
}

func (r *RepositoryMock) GetToken(ctx context.Context, tokenID string) (*models.RefreshToken, error) {
	args := r.Called(ctx, tokenID)
	return args.Get(0).(*models.RefreshToken), args.Error(1)
}

func (r *RepositoryMock) SendMail(address string, text string) error {
	args := r.Called(address, text)
	return args.Error(0)
}

func NewRepositoryMock() *RepositoryMock {
	return &RepositoryMock{}
}
