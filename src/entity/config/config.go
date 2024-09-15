package config

import "os"

type Config struct {
	JWTSignString string
	ConnStr       string
}

func NewConfig() *Config {
	return &Config{
		JWTSignString: os.Getenv("JWT_SECRET"),
		ConnStr:       os.Getenv("CONN_STR"),
	}
}
