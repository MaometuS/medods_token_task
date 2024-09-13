package repository

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/maometus/medods_token_task/src/entity"
	"github.com/maometus/medods_token_task/src/entity/config"
	"github.com/maometus/medods_token_task/src/entity/models"
	"github.com/maometus/medods_token_task/src/use_case"
	"log"
)

type repository struct {
	config *config.Config
}

func (r *repository) GenerateJWT(claims map[string]any) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims(claims))

	tokenString, err := token.SignedString([]byte(r.config.JWTSignString))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (r *repository) GetJWTClaims(token string) (map[string]any, error) {
	tokenObj, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return []byte(r.config.JWTSignString), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := tokenObj.Claims.(jwt.MapClaims); ok {
		return claims, nil
	} else {
		return nil, errors.New("invalid claims on jwt")
	}
}

func (r *repository) CreateToken(ctx context.Context, token *models.RefreshToken) error {
	db, ok := ctx.Value("db").(entity.PgxIface)
	if !ok {
		return errors.New("db not found in context")
	}

	_, err := db.Exec(
		ctx,
		"insert into tokens(token, token_id, valid, created_at, updated_at) values ($1, $2, $3, $4, $5)",
		token.Token,
		token.TokenID,
		token.Valid,
		token.CreatedAt,
		token.UpdatedAt,
	)
	if err != nil {
		return err
	}

	return nil
}

func (r *repository) UpdateToken(ctx context.Context, token *models.RefreshToken) error {
	db, ok := ctx.Value("db").(entity.PgxIface)
	if !ok {
		return errors.New("db not found in context")
	}

	_, err := db.Exec(
		ctx,
		"update tokens set valid = $1, updated_at = $2 where token_id = $3",
		token.Valid,
		token.UpdatedAt,
		token.TokenID,
	)
	if err != nil {
		return err
	}

	return nil
}

func (r *repository) GetToken(ctx context.Context, tokenID string) (*models.RefreshToken, error) {
	db, ok := ctx.Value("db").(entity.PgxIface)
	if !ok {
		return nil, errors.New("db not found in context")
	}

	rows, err := db.Query(ctx, "select * from tokens where token_id = $1", tokenID)
	if err != nil {
		return nil, err
	}

	token, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.RefreshToken])
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func (r *repository) SendMail(address string, text string) error {
	log.Println(address, text, "email sent")
	return nil
}

func NewRepository(config *config.Config) use_case.Repository {
	return &repository{config}
}
