package interactor

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/maometus/medods_token_task/src/entity/models"
	"github.com/maometus/medods_token_task/src/use_case"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"slices"
	"strings"
	"testing"
)

func TestInteractor_GetTokens(t *testing.T) {
	type testCase struct {
		repo *use_case.RepositoryMock
		ctx  context.Context
		id   string
		ip   string

		activeToken  string
		refreshToken string
		err          error
	}

	cases := []testCase{
		{
			use_case.NewRepositoryMock(),
			context.Background(),
			"123321",
			"ip",
			"",
			"",
			errors.New("invalid UUID length: 6"),
		},
	}

	repo1 := use_case.NewRepositoryMock()
	repo1.On("GenerateJWT", mock.MatchedBy(func(claims map[string]any) bool {
		return claims["uuid"] == "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4" && claims["ip"] == "127.0.0.1"
	})).Return("", errors.New("could not generate active token"))

	cases = append(cases, testCase{
		repo:         repo1,
		ctx:          context.Background(),
		id:           "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4",
		ip:           "127.0.0.1",
		activeToken:  "",
		refreshToken: "",
		err:          errors.New("could not generate active token"),
	})

	repo2 := use_case.NewRepositoryMock()

	repo2.On("GenerateJWT", mock.MatchedBy(func(claims map[string]any) bool {
		return claims["uuid"] == "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4" && claims["ip"] == "127.0.0.1"
	})).Return("new_token", nil).Return("", errors.New("could not generate refresh token"))

	cases = append(cases, testCase{
		repo:         repo2,
		ctx:          context.Background(),
		id:           "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4",
		ip:           "127.0.0.1",
		activeToken:  "",
		refreshToken: "",
		err:          errors.New("could not generate refresh token"),
	})

	repo3 := use_case.NewRepositoryMock()
	repo3.On("GenerateJWT", mock.MatchedBy(func(claims map[string]any) bool {
		return claims["uuid"] == "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4" && claims["ip"] == "127.0.0.1"
	})).Return("new_token", nil).Once()
	repo3.On("GenerateJWT", mock.MatchedBy(func(claims map[string]any) bool {
		return claims["uuid"] == "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4" && claims["ip"] == "127.0.0.1"
	})).Return(strings.Repeat("a", 512), nil).Once()
	repo3.On("CreateToken", context.Background(), mock.MatchedBy(func(token *models.RefreshToken) bool {
		refreshToken := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 512)))
		refreshTokenReversed := []byte(refreshToken)
		slices.Reverse(refreshTokenReversed)

		err := bcrypt.CompareHashAndPassword([]byte(token.Token), refreshTokenReversed[:72])
		if err != nil {
			return false
		}

		return token.Valid
	})).Return(errors.New("could not create token"))

	cases = append(cases, testCase{
		repo:         repo3,
		ctx:          context.Background(),
		id:           "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4",
		ip:           "127.0.0.1",
		activeToken:  "",
		refreshToken: "",
		err:          errors.New("could not create token"),
	})

	repo4 := use_case.NewRepositoryMock()
	repo4.On("GenerateJWT", mock.MatchedBy(func(claims map[string]any) bool {
		return claims["uuid"] == "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4" && claims["ip"] == "127.0.0.1"
	})).Return("new_token", nil).Once()
	repo4.On("GenerateJWT", mock.MatchedBy(func(claims map[string]any) bool {
		return claims["uuid"] == "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4" && claims["ip"] == "127.0.0.1"
	})).Return(strings.Repeat("a", 512), nil).Once()
	repo4.On("CreateToken", context.Background(), mock.MatchedBy(func(token *models.RefreshToken) bool {
		refreshToken := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 512)))
		refreshTokenReversed := []byte(refreshToken)
		slices.Reverse(refreshTokenReversed)

		err := bcrypt.CompareHashAndPassword([]byte(token.Token), refreshTokenReversed[:72])
		if err != nil {
			return false
		}

		return token.Valid
	})).Return(nil)

	cases = append(cases, testCase{
		repo:         repo4,
		ctx:          context.Background(),
		id:           "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4",
		ip:           "127.0.0.1",
		activeToken:  "new_token",
		refreshToken: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 512))),
		err:          nil,
	})

	for i, el := range cases {
		actTok, refTok, err := NewInteractor(el.repo).GetTokens(el.ctx, el.id, el.ip)
		if err != nil && el.err != nil && err.Error() != el.err.Error() {
			t.Error(fmt.Sprintf("error don't match %d, %v", i, err))
		} else if err != nil && el.err == nil {
			t.Error("did not expect error: " + err.Error())
		}

		if actTok != el.activeToken || refTok != el.refreshToken {
			t.Error("results don't match")
		}

		el.repo.AssertExpectations(t)
	}
}

func TestInteractor_RefreshTokens(t *testing.T) {
	type testCase struct {
		repo         *use_case.RepositoryMock
		ctx          context.Context
		activeToken  string
		refreshToken string
		ip           string

		activeTokenResp  string
		refreshTokenResp string
		err              error
	}
	cases := make([]testCase, 0)

	repo1 := use_case.NewRepositoryMock()
	repo1.On("GetJWTClaims", "token").Return(make(map[string]any), errors.New("could not parse jwt")).Once()

	cases = append(cases, testCase{
		repo:             repo1,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "",
		ip:               "",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("could not parse jwt"),
	})

	repo2 := use_case.NewRepositoryMock()
	repo2.On("GetJWTClaims", "token").Return(make(map[string]any), nil).Once()
	repo2.On("GetJWTClaims", "ref_token").Return(make(map[string]any), errors.New("could not parse refresh jwt")).Once()

	cases = append(cases, testCase{
		repo:             repo2,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "cmVmX3Rva2Vu",
		ip:               "",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("could not parse refresh jwt"),
	})

	repo3 := use_case.NewRepositoryMock()
	repo3.On("GetJWTClaims", "token").Return(make(map[string]any), nil).Once()
	repo3.On("GetJWTClaims", "ref_token").Return(make(map[string]any), nil).Once()

	cases = append(cases, testCase{
		repo:             repo3,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "cmVmX3Rva2Vu",
		ip:               "",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("uuid not found on active token"),
	})

	repo4 := use_case.NewRepositoryMock()
	repo4.On("GetJWTClaims", "token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()
	repo4.On("GetJWTClaims", "ref_token").Return(make(map[string]any), nil).Once()

	cases = append(cases, testCase{
		repo:             repo4,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "cmVmX3Rva2Vu",
		ip:               "",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("uuid not found on refresh token"),
	})

	repo5 := use_case.NewRepositoryMock()
	repo5.On("GetJWTClaims", "token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()
	repo5.On("GetJWTClaims", "ref_token").Return(map[string]any{
		"token_id": "321123",
	}, nil).Once()

	cases = append(cases, testCase{
		repo:             repo5,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "cmVmX3Rva2Vu",
		ip:               "",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("refresh token does not match active token"),
	})

	repo6 := use_case.NewRepositoryMock()
	repo6.On("GetJWTClaims", "token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()
	repo6.On("GetJWTClaims", "ref_token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()

	cases = append(cases, testCase{
		repo:             repo6,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "cmVmX3Rva2Vu",
		ip:               "",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("ip not found on refresh token"),
	})

	repo7 := use_case.NewRepositoryMock()
	repo7.On("GetJWTClaims", "token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()
	repo7.On("GetJWTClaims", "ref_token").Return(map[string]any{
		"token_id": "123321",
		"ip":       "127.0.0.2",
	}, nil).Once()
	repo7.On("SendMail", "usermail@dummy.ru", "attempt made from different device").Return(nil).Once()

	cases = append(cases, testCase{
		repo:             repo7,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "cmVmX3Rva2Vu",
		ip:               "127.0.0.1",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("ip does not match"),
	})

	repo8 := use_case.NewRepositoryMock()
	repo8.On("GetJWTClaims", "token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()
	repo8.On("GetJWTClaims", "ref_token").Return(map[string]any{
		"token_id": "123321",
		"ip":       "127.0.0.1",
	}, nil).Once()
	repo8.On("GetToken", context.Background(), "123321").Return(&models.RefreshToken{}, errors.New("could not get token")).Once()

	cases = append(cases, testCase{
		repo:             repo8,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "cmVmX3Rva2Vu",
		ip:               "127.0.0.1",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("could not get token"),
	})

	repo9 := use_case.NewRepositoryMock()
	repo9.On("GetJWTClaims", "token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()
	repo9.On(
		"GetJWTClaims",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	).Return(map[string]any{
		"token_id": "123321",
		"ip":       "127.0.0.1",
	}, nil).Once()
	refTok := &models.RefreshToken{
		Token: "$2a$04$jMvDqxhYVjl5InzmdzwfreNcCrrht6MBP/ZC1mQGpDIFenc6OnhZy",
	}
	repo9.On("GetToken", context.Background(), "123321").Return(refTok, nil).Once()

	cases = append(cases, testCase{
		repo:             repo9,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		ip:               "127.0.0.1",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("crypto/bcrypt: hashedPassword is not the hash of the given password"),
	})

	repo10 := use_case.NewRepositoryMock()
	repo10.On("GetJWTClaims", "token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()
	repo10.On(
		"GetJWTClaims",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	).Return(map[string]any{
		"token_id": "123321",
		"ip":       "127.0.0.1",
	}, nil).Once()

	refreshTokenReversed := []byte("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
	slices.Reverse(refreshTokenReversed)
	pass, err := bcrypt.GenerateFromPassword(refreshTokenReversed[:72], 4)
	if err != nil {
		t.Error(err)
	}

	refTok = &models.RefreshToken{
		Token: string(pass),
		Valid: false,
	}
	repo10.On("GetToken", context.Background(), "123321").Return(refTok, nil).Once()

	cases = append(cases, testCase{
		repo:             repo10,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		ip:               "127.0.0.1",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("refresh token invalid"),
	})

	repo11 := use_case.NewRepositoryMock()
	repo11.On("GetJWTClaims", "token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()
	repo11.On(
		"GetJWTClaims",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	).Return(map[string]any{
		"token_id": "123321",
		"ip":       "127.0.0.1",
	}, nil).Once()

	refreshTokenReversed = []byte("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
	slices.Reverse(refreshTokenReversed)
	pass, err = bcrypt.GenerateFromPassword(refreshTokenReversed[:72], 4)
	if err != nil {
		t.Error(err)
	}

	refTok = &models.RefreshToken{
		Token: string(pass),
		Valid: true,
	}
	repo11.On("GetToken", context.Background(), "123321").Return(refTok, nil).Once()
	repo11.On("UpdateToken", context.Background(), mock.MatchedBy(func(tok *models.RefreshToken) bool {
		return !tok.Valid
	})).Return(errors.New("could not update token")).Once()

	cases = append(cases, testCase{
		repo:             repo11,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		ip:               "127.0.0.1",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("could not update token"),
	})

	repo12 := use_case.NewRepositoryMock()
	repo12.On("GetJWTClaims", "token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()
	repo12.On(
		"GetJWTClaims",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	).Return(map[string]any{
		"token_id": "123321",
		"ip":       "127.0.0.1",
	}, nil).Once()

	refreshTokenReversed = []byte("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
	slices.Reverse(refreshTokenReversed)
	pass, err = bcrypt.GenerateFromPassword(refreshTokenReversed[:72], 4)
	if err != nil {
		t.Error(err)
	}

	refTok = &models.RefreshToken{
		Token: string(pass),
		Valid: true,
	}
	repo12.On("GetToken", context.Background(), "123321").Return(refTok, nil).Once()
	repo12.On("UpdateToken", context.Background(), mock.MatchedBy(func(tok *models.RefreshToken) bool {
		return !tok.Valid
	})).Return(nil).Once()

	cases = append(cases, testCase{
		repo:             repo12,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		ip:               "127.0.0.1",
		activeTokenResp:  "",
		refreshTokenResp: "",
		err:              errors.New("uuid not found on refresh token"),
	})

	repo13 := use_case.NewRepositoryMock()
	repo13.On("GetJWTClaims", "token").Return(map[string]any{
		"token_id": "123321",
	}, nil).Once()
	repo13.On(
		"GetJWTClaims",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	).Return(map[string]any{
		"token_id": "123321",
		"uuid":     "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4",
		"ip":       "127.0.0.1",
	}, nil).Once()

	refreshTokenReversed = []byte("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=")
	slices.Reverse(refreshTokenReversed)
	pass, err = bcrypt.GenerateFromPassword(refreshTokenReversed[:72], 4)
	if err != nil {
		t.Error(err)
	}

	refTok = &models.RefreshToken{
		Token: string(pass),
		Valid: true,
	}
	repo13.On("GetToken", context.Background(), "123321").Return(refTok, nil).Once()
	repo13.On("UpdateToken", context.Background(), mock.MatchedBy(func(tok *models.RefreshToken) bool {
		return !tok.Valid
	})).Return(nil).Once()

	repo13.On("GenerateJWT", mock.MatchedBy(func(claims map[string]any) bool {
		return claims["uuid"] == "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4" && claims["ip"] == "127.0.0.1"
	})).Return("new_token", nil).Once()
	repo13.On("GenerateJWT", mock.MatchedBy(func(claims map[string]any) bool {
		return claims["uuid"] == "cb2f8d3f-7d92-46a4-b3a9-7a917e43f3c4" && claims["ip"] == "127.0.0.1"
	})).Return(strings.Repeat("a", 512), nil).Once()
	repo13.On("CreateToken", context.Background(), mock.MatchedBy(func(token *models.RefreshToken) bool {
		refreshToken := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 512)))
		refreshTokenReversed := []byte(refreshToken)
		slices.Reverse(refreshTokenReversed)

		err := bcrypt.CompareHashAndPassword([]byte(token.Token), refreshTokenReversed[:72])
		if err != nil {
			return false
		}

		return token.Valid
	})).Return(nil)

	cases = append(cases, testCase{
		repo:             repo13,
		ctx:              context.Background(),
		activeToken:      "token",
		refreshToken:     "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		ip:               "127.0.0.1",
		activeTokenResp:  "new_token",
		refreshTokenResp: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		err:              nil,
	})

	for i, el := range cases {
		actTok, refTok, err := NewInteractor(el.repo).RefreshTokens(el.ctx, el.activeToken, el.refreshToken, el.ip)
		if err != nil && el.err != nil && err.Error() != el.err.Error() {
			t.Error(fmt.Sprintf("error don't match %d, %v", i, err))
		} else if err != nil && el.err == nil {
			t.Error("did not expect error: " + err.Error())
		}

		if actTok != el.activeTokenResp || refTok != el.refreshTokenResp {
			fmt.Println(actTok)
			fmt.Println(refTok)
			t.Error("results don't match")
		}

		el.repo.AssertExpectations(t)
	}
}
