package main

import (
	"fmt"
	"github.com/maometus/medods_token_task/src/entity/config"
	"github.com/maometus/medods_token_task/src/infrastructure"
	"github.com/maometus/medods_token_task/src/interface/controller"
	"github.com/maometus/medods_token_task/src/interface/repository"
	"github.com/maometus/medods_token_task/src/use_case/interactor"
	"net/http"
)

func main() {
	conf := config.NewConfig()

	db, err := infrastructure.NewDatabase(conf)
	if err != nil {
		panic("error db")
	}

	app := controller.NewController(
		interactor.NewInteractor(repository.NewRepository(conf)),
		db,
	)

	mux := infrastructure.NewRouter(app)

	fmt.Println("Listening on 8080")
	http.ListenAndServe(":8080", mux)
}
