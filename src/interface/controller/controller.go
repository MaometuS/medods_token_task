package controller

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/maometus/medods_token_task/src/use_case/interactor"
	"net/http"
	"strings"
)

type Controller interface {
	GetTokens(w http.ResponseWriter, r *http.Request)
	RefreshTokens(w http.ResponseWriter, r *http.Request)
}

type controller struct {
	interactor interactor.Interactor
	db         *pgxpool.Pool
}

func (c *controller) GetTokens(w http.ResponseWriter, r *http.Request) {
	activeToken, refreshToken, err := c.interactor.GetTokens(
		context.WithValue(r.Context(), "db", c.db),
		r.URL.Query().Get("uuid"),
		strings.Split(r.RemoteAddr, ":")[0],
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"active_token":  activeToken,
		"refresh_token": refreshToken,
	})
}

func (c *controller) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	activeToken := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
	refreshToken := r.Header.Get("Refresh-Token")
	ip := strings.Split(r.RemoteAddr, ":")[0]

	activeToken, refreshToken, err := c.interactor.RefreshTokens(
		context.WithValue(r.Context(), "db", c.db),
		activeToken,
		refreshToken,
		ip,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"active_token":  activeToken,
		"refresh_token": refreshToken,
	})
}

func NewController(interactor interactor.Interactor, db *pgxpool.Pool) Controller {
	return &controller{interactor, db}
}
