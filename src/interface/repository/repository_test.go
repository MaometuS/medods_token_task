package repository

import (
	"context"
	"errors"
	"fmt"
	"github.com/maometus/medods_token_task/src/entity/config"
	"github.com/maometus/medods_token_task/src/entity/models"
	"github.com/pashagolub/pgxmock/v3"
	"reflect"
	"testing"
	"time"
)

func TestRepository_GenerateJWT(t *testing.T) {
	repo := NewRepository(&config.Config{JWTSignString: "jwt_secret"})

	token, err := repo.GenerateJWT(map[string]any{
		"iss":  "issuer",
		"some": "example",
	})
	if err != nil {
		t.Error(err)
	}

	if token != "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzb21lIjoiZXhhbXBsZSJ9.UJKUALE9o75HQAJMYWo7iEYZmp62ffnEkxdM_nZ1k6xaDVyCmGUTTUaTUxmaloCGuK4WW9B0BcHMuOjFiuXQEg" {
		t.Error("token incorrect")
	}
}

func TestRepository_GetJWTClaims(t *testing.T) {
	repo := NewRepository(&config.Config{JWTSignString: "jwt_secret"})

	claims, err := repo.GetJWTClaims("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzb21lIjoiZXhhbXBsZSJ9.UJKUALE9o75HQAJMYWo7iEYZmp62ffnEkxdM_nZ1k6xaDVyCmGUTTUaTUxmaloCGuK4WW9B0BcHMuOjFiuXQEg")
	if err != nil {
		t.Error(err)
	}

	some, ok := claims["some"]
	if !ok {
		t.Error("some claim does not exist")
	}

	if some != "example" {
		t.Error("claim does not match")
	}
}

func TestRepository_CreateToken(t *testing.T) {
	repo := NewRepository(&config.Config{})

	type testCase struct {
		ctx    context.Context
		mockDB pgxmock.PgxPoolIface
		token  *models.RefreshToken

		err error
	}

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherEqual))
	if err != nil {
		t.Error(err)
	}

	now := time.Now()

	mock.ExpectExec(
		"insert into tokens(token, token_id, valid, created_at, updated_at) values ($1, $2, $3, $4, $5)",
	).WithArgs(
		"token",
		"token_id",
		true,
		now,
		now,
	).WillReturnResult(pgxmock.NewResult("INSERT", 1))

	cases := []testCase{
		{
			context.Background(),
			nil,
			&models.RefreshToken{
				Token:     "token",
				TokenID:   "token_id",
				Valid:     true,
				CreatedAt: now,
				UpdatedAt: now,
			},
			errors.New("db not found in context"),
		},
		{
			context.WithValue(context.Background(), "db", mock),
			mock,
			&models.RefreshToken{
				Token:     "token",
				TokenID:   "token_id",
				Valid:     true,
				CreatedAt: now,
				UpdatedAt: now,
			},
			nil,
		},
	}

	for i, el := range cases {
		err := repo.CreateToken(el.ctx, el.token)
		if err != nil && el.err != nil && err.Error() != el.err.Error() {
			t.Error(fmt.Sprintf("error don't match %d, %v", i, err))
		} else if err != nil && el.err == nil {
			t.Error("did not expect error: " + err.Error())
		}

		if el.mockDB != nil {
			err = el.mockDB.ExpectationsWereMet()
			if err != nil {
				t.Error(err)
			}
		}
	}
}

func TestRepository_UpdateToken(t *testing.T) {
	repo := NewRepository(&config.Config{})

	type testCase struct {
		ctx    context.Context
		mockDB pgxmock.PgxPoolIface
		token  *models.RefreshToken

		err error
	}

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherEqual))
	if err != nil {
		t.Error(err)
	}

	now := time.Now()

	mock.ExpectExec(
		"update tokens set valid = $1, updated_at = $2 where token_id = $3",
	).WithArgs(
		true,
		now,
		"token_id",
	).WillReturnResult(pgxmock.NewResult("INSERT", 1))

	cases := []testCase{
		{
			context.Background(),
			nil,
			&models.RefreshToken{
				Token:     "token",
				TokenID:   "token_id",
				Valid:     true,
				CreatedAt: now,
				UpdatedAt: now,
			},
			errors.New("db not found in context"),
		},
		{
			context.WithValue(context.Background(), "db", mock),
			mock,
			&models.RefreshToken{
				Token:     "token",
				TokenID:   "token_id",
				Valid:     true,
				CreatedAt: now,
				UpdatedAt: now,
			},
			nil,
		},
	}

	for i, el := range cases {
		err := repo.UpdateToken(el.ctx, el.token)
		if err != nil && el.err != nil && err.Error() != el.err.Error() {
			t.Error(fmt.Sprintf("error don't match %d, %v", i, err))
		} else if err != nil && el.err == nil {
			t.Error("did not expect error: " + err.Error())
		}

		if el.mockDB != nil {
			err = el.mockDB.ExpectationsWereMet()
			if err != nil {
				t.Error(err)
			}
		}
	}
}

func TestRepository_GetToken(t *testing.T) {
	repo := NewRepository(&config.Config{})

	type testCase struct {
		ctx     context.Context
		mockDB  pgxmock.PgxPoolIface
		tokenID string

		token *models.RefreshToken
		err   error
	}

	now := time.Now()

	mock, err := pgxmock.NewPool(pgxmock.QueryMatcherOption(pgxmock.QueryMatcherEqual))
	if err != nil {
		t.Error(err)
	}

	mock.ExpectQuery(
		"select * from tokens where token_id = $1",
	).WithArgs("token_id").WillReturnRows(
		pgxmock.NewRows(
			[]string{"id", "token", "token_id", "valid", "created_at", "updated_at"},
		).AddRow(int64(1), "token", "token_id", true, now, now),
	)

	cases := []testCase{
		{
			context.Background(),
			nil,
			"",
			nil,
			errors.New("db not found in context"),
		},
		{
			context.WithValue(context.Background(), "db", mock),
			mock,
			"token_id",
			&models.RefreshToken{
				ID:        1,
				Token:     "token",
				TokenID:   "token_id",
				Valid:     true,
				CreatedAt: now,
				UpdatedAt: now,
			},
			nil,
		},
	}

	for i, el := range cases {
		res, err := repo.GetToken(el.ctx, el.tokenID)
		if err != nil && el.err != nil && err.Error() != el.err.Error() {
			t.Error(fmt.Sprintf("error don't match %d, %v", i, err))
		} else if err != nil && el.err == nil {
			t.Error("did not expect error: " + err.Error())
		}

		if !reflect.DeepEqual(res, el.token) {
			t.Error("results don't match")
		}

		if el.mockDB != nil {
			err = el.mockDB.ExpectationsWereMet()
			if err != nil {
				t.Error(err)
			}
		}
	}
}
