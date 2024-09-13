package infrastructure

import (
	"github.com/maometus/medods_token_task/src/interface/controller"
	"net/http"
)

func NewRouter(c controller.Controller) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /get_tokens", c.GetTokens)
	mux.HandleFunc("GET /refresh_tokens", c.RefreshTokens)

	return mux
}
