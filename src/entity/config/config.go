package config

type Config struct {
	JWTSignString string
}

func NewConfig() *Config {
	return &Config{}
}
