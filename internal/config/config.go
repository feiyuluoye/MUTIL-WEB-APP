package config

import (
	"os"
	"strconv"
)

type Config struct {
	ServerPort          string
	DBPath              string
	JWTSecret           string
	EnableAuth          bool
	LogLevel            string
	MaxServices         int
	HealthCheckInterval int
}

func Load() *Config {
	return &Config{
		ServerPort:          getEnv("SERVER_PORT", "8080"),
		DBPath:              getEnv("DB_PATH", "./services.db"),
		JWTSecret:           getEnv("JWT_SECRET", "your-secret-key"),
		EnableAuth:          getEnvAsBool("ENABLE_AUTH", false),
		LogLevel:            getEnv("LOG_LEVEL", "info"),
		MaxServices:         getEnvAsInt("MAX_SERVICES", 100),
		HealthCheckInterval: getEnvAsInt("HEALTH_CHECK_INTERVAL", 30),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}
