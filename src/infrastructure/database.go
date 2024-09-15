package infrastructure

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/maometus/medods_token_task/src/entity/config"
	"time"
)

func NewDatabase(conf *config.Config) (*pgxpool.Pool, error) {
	var db *pgxpool.Pool
	var err error

	fmt.Println("Waiting for database")

	for {
		db, err = pgxpool.New(context.Background(), conf.ConnStr)
		if err == nil {
			break
		}

		fmt.Println(err)
		time.Sleep(time.Second * 2)
	}
	defer db.Close()

	var exists bool
	err = db.QueryRow(context.Background(), "select exists (select datname from pg_catalog.pg_database where datname = $1)", "tokenizer").Scan(&exists)
	if err != nil {
		return nil, err
	}

	if !exists {
		err = migrate(db, conf.ConnStr)
		if err != nil {
			return nil, err
		}
	}

	tokenizerDB, err := pgxpool.New(context.Background(), conf.ConnStr+"/tokenizer")
	if err != nil {
		return nil, err
	}

	fmt.Println("Connected to database")

	return tokenizerDB, nil
}

func migrate(db *pgxpool.Pool, connStr string) error {
	_, err := db.Exec(context.Background(), "create database tokenizer")
	if err != nil {
		return err
	}

	tokenizerDB, err := pgxpool.New(context.Background(), connStr+"/tokenizer")
	if err != nil {
		return err
	}

	_, err = tokenizerDB.Exec(
		context.Background(),
		`create table tokens(
			id bigserial primary key,
			token varchar,
			token_id varchar,
			valid bool,
			created_at timestamp,
			updated_at timestamp
		)`)
	if err != nil {
		return err
	}
	defer tokenizerDB.Close()

	return nil
}
