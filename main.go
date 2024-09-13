package main

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/maometus/medods_token_task/src/entity/config"
	"github.com/maometus/medods_token_task/src/infrastructure"
	"github.com/maometus/medods_token_task/src/interface/controller"
	"github.com/maometus/medods_token_task/src/interface/repository"
	"github.com/maometus/medods_token_task/src/use_case/interactor"
	"net/http"
)

func main() {
	conf := config.NewConfig()

	db, err := pgxpool.New(context.Background(), "")
	if err != nil {
		panic("error db")
	}

	app := controller.NewController(
		interactor.NewInteractor(repository.NewRepository(conf)),
		db,
	)

	mux := infrastructure.NewRouter(app)

	http.ListenAndServe(":8080", mux)
}
