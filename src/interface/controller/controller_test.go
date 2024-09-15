package controller

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/maometus/medods_token_task/src/use_case/interactor"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestController_GetTokens(t *testing.T) {
	type testCase struct {
		req        *http.Request
		resp       *httptest.ResponseRecorder
		code       int
		interactor *interactor.InteractorMock
	}

	cases := make([]testCase, 0)

	req := httptest.NewRequest("GET", "https://localhost/admin/get_tokens?uuid=some_uuid", nil)
	req.RemoteAddr = "127.0.0.1"
	resp := httptest.NewRecorder()
	i := interactor.NewInteractorMock()
	var pool *pgxpool.Pool
	i.On("GetTokens", context.WithValue(req.Context(), "db", pool), "some_uuid", "127.0.0.1").Return("", "", errors.New("could not get tokens")).Once()

	cases = append(cases, testCase{
		req:        req,
		resp:       resp,
		code:       500,
		interactor: i,
	})

	req = httptest.NewRequest("GET", "https://localhost/admin/get_tokens?uuid=some_uuid", nil)
	req.RemoteAddr = "127.0.0.1"
	resp = httptest.NewRecorder()
	i = interactor.NewInteractorMock()
	i.On("GetTokens", context.WithValue(req.Context(), "db", pool), "some_uuid", "127.0.0.1").Return("", "", nil).Once()

	cases = append(cases, testCase{
		req:        req,
		resp:       resp,
		code:       200,
		interactor: i,
	})

	for i, el := range cases {
		controller := NewController(el.interactor, nil)
		controller.GetTokens(el.resp, el.req)

		if el.resp.Code != el.code {
			t.Error("codes don't match: ", i)
		}

		if el.interactor != nil {
			el.interactor.AssertExpectations(t)
		}
	}
}

func TestController_RefreshTokens(t *testing.T) {
	type testCase struct {
		req        *http.Request
		resp       *httptest.ResponseRecorder
		code       int
		interactor *interactor.InteractorMock
	}

	cases := make([]testCase, 0)

	req := httptest.NewRequest("GET", "https://localhost/admin/refresh_tokens/", nil)
	req.Header.Set("Authorization", "Bearer act_tok")
	req.Header.Set("Refresh-Token", "ref_tok")
	req.RemoteAddr = "127.0.0.1"
	resp := httptest.NewRecorder()
	i := interactor.NewInteractorMock()
	var pool *pgxpool.Pool
	i.On("RefreshTokens", context.WithValue(req.Context(), "db", pool), "act_tok", "ref_tok", "127.0.0.1").Return("", "", errors.New("could not refresh tokens")).Once()

	cases = append(cases, testCase{
		req:        req,
		resp:       resp,
		code:       500,
		interactor: i,
	})

	req = httptest.NewRequest("GET", "https://localhost/admin/refresh_tokens/", nil)
	req.Header.Set("Authorization", "Bearer act_tok")
	req.Header.Set("Refresh-Token", "ref_tok")
	req.RemoteAddr = "127.0.0.1"
	resp = httptest.NewRecorder()
	i = interactor.NewInteractorMock()
	i.On("RefreshTokens", context.WithValue(req.Context(), "db", pool), "act_tok", "ref_tok", "127.0.0.1").Return("", "", nil).Once()

	cases = append(cases, testCase{
		req:        req,
		resp:       resp,
		code:       200,
		interactor: i,
	})

	for i, el := range cases {
		controller := NewController(el.interactor, nil)
		controller.RefreshTokens(el.resp, el.req)

		if el.resp.Code != el.code {
			t.Error("codes don't match: ", i)
		}

		if el.interactor != nil {
			el.interactor.AssertExpectations(t)
		}
	}
}
