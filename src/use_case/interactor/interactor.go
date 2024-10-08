package interactor

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"github.com/maometus/medods_token_task/src/entity/models"
	"github.com/maometus/medods_token_task/src/use_case"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"slices"
	"time"
)

type Interactor interface {
	GetTokens(ctx context.Context, id string, ip string) (string, string, error)
	RefreshTokens(ctx context.Context, activeToken string, refreshToken string, ip string) (string, string, error)
}

type interactor struct {
	repository use_case.Repository
}

func (i *interactor) GetTokens(ctx context.Context, id string, ip string) (string, string, error) {
	_, err := uuid.Parse(id)
	if err != nil {
		return "", "", err
	}

	newTokenID := uuid.NewString()

	activeToken, err := i.repository.GenerateJWT(map[string]any{
		"ip":       ip,
		"uuid":     id,
		"token_id": newTokenID,
	})
	if err != nil {
		return "", "", err
	}

	refreshTokenJWT, err := i.repository.GenerateJWT(map[string]any{
		"ip":       ip,
		"uuid":     id,
		"token_id": newTokenID,
	})
	if err != nil {
		return "", "", err
	}

	refreshToken := base64.StdEncoding.EncodeToString([]byte(refreshTokenJWT))
	refreshTokenReversed := []byte(refreshToken)
	slices.Reverse(refreshTokenReversed)

	refreshTokenEncrypted, err := bcrypt.GenerateFromPassword(refreshTokenReversed[:72], 4)
	if err != nil {
		return "", "", err
	}

	err = i.repository.CreateToken(ctx, &models.RefreshToken{
		Token:     string(refreshTokenEncrypted),
		TokenID:   newTokenID,
		Valid:     true,
		UpdatedAt: time.Now(),
		CreatedAt: time.Now(),
	})
	if err != nil {
		return "", "", err
	}

	return activeToken, refreshToken, nil
}

func (i *interactor) RefreshTokens(ctx context.Context, activeToken string, refreshToken string, ip string) (string, string, error) {
	activeTokenClaims, err := i.repository.GetJWTClaims(activeToken)
	if err != nil {
		return "", "", err
	}

	refreshTokenJWT, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		return "", "", err
	}

	refreshTokenClaims, err := i.repository.GetJWTClaims(string(refreshTokenJWT))
	if err != nil {
		return "", "", err
	}

	activeTokenID, ok := activeTokenClaims["token_id"].(string)
	if !ok {
		return "", "", errors.New("uuid not found on active token")
	}

	refreshTokenID, ok := refreshTokenClaims["token_id"].(string)
	if !ok {
		return "", "", errors.New("uuid not found on refresh token")
	}

	if activeTokenID != refreshTokenID {
		return "", "", errors.New("refresh token does not match active token")
	}

	refreshTokenIP, ok := refreshTokenClaims["ip"].(string)
	if !ok {
		return "", "", errors.New("ip not found on refresh token")
	}

	if refreshTokenIP != ip {
		i.repository.SendMail("usermail@dummy.ru", "attempt made from different device")

		return "", "", errors.New("ip does not match")
	}

	savedToken, err := i.repository.GetToken(ctx, refreshTokenID)
	if err != nil {
		return "", "", err
	}

	refreshTokenReversed := []byte(refreshToken)
	slices.Reverse(refreshTokenReversed)

	err = bcrypt.CompareHashAndPassword([]byte(savedToken.Token), refreshTokenReversed[:72])
	if err != nil {
		return "", "", err
	}

	if !savedToken.Valid {
		return "", "", errors.New("refresh token invalid")
	}

	savedToken.Valid = false
	savedToken.UpdatedAt = time.Now()
	err = i.repository.UpdateToken(ctx, savedToken)
	if err != nil {
		return "", "", err
	}

	refreshUUID, ok := refreshTokenClaims["uuid"].(string)
	if !ok {
		return "", "", errors.New("uuid not found on refresh token")
	}

	return i.GetTokens(ctx, refreshUUID, ip)
}

func NewInteractor(rep use_case.Repository) Interactor {
	return &interactor{rep}
}

type InteractorMock struct {
	mock.Mock
}

func (i *InteractorMock) GetTokens(ctx context.Context, id string, ip string) (string, string, error) {
	args := i.Called(ctx, id, ip)
	return args.String(0), args.String(1), args.Error(2)
}

func (i *InteractorMock) RefreshTokens(ctx context.Context, activeToken string, refreshToken string, ip string) (string, string, error) {
	args := i.Called(ctx, activeToken, refreshToken, ip)
	return args.String(0), args.String(1), args.Error(2)
}

func NewInteractorMock() *InteractorMock {
	return &InteractorMock{}
}
