package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	AdminAPIKey string

	IPv6Range string
	Interface string
	Port      string

	DBRefreshInterval time.Duration
	DefaultThreadLimit int
}

func LoadConfig() *Config {
	err := godotenv.Load()
	if err != nil {
		createDefaultEnvFile()
		_ = godotenv.Load()
	}

	config := &Config{
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "3306"),
		DBUser:     getEnv("DB_USER", "root"),
		DBPassword: getEnv("DB_PASSWORD", ""),
		DBName:     getEnv("DB_NAME", "proxy"),
		AdminAPIKey: getEnv("ADMIN_API_KEY", "change_me_in_env_file"),

		IPv6Range: getEnv("IPV6_RANGE", "2605:6400:49f2::/48"),
		Interface: getEnv("INTERFACE", ""),
		Port:      getEnv("PORT", "7777"),

		DBRefreshInterval: getDurationEnv("DB_REFRESH_INTERVAL", 5*time.Minute),
		DefaultThreadLimit: getIntEnv("DEFAULT_THREAD_LIMIT", 100),
	}

	if config.IPv6Range == "" {
		log.Fatal("Error: IPV6_RANGE not set in .env file")
	}

	return config
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getIntEnv(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		log.Printf("Warning: Invalid value for %s, using default: %v", key, defaultValue)
		return defaultValue
	}
	return value
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	
	valueInt, err := strconv.Atoi(valueStr)
	if err == nil {
		return time.Duration(valueInt) * time.Minute
	}
	
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		log.Printf("Warning: Invalid duration for %s, using default: %v", key, defaultValue)
		return defaultValue
	}
	return value
}

func createDefaultEnvFile() {
	content := `# Network Configuration
IPV6_RANGE=2605:6400:49f2::/48
PORT=7777

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=proxy
ADMIN_API_KEY=change_me_to_secure_api_key

# Application Configuration
DB_REFRESH_INTERVAL=5m
DEFAULT_THREAD_LIMIT=100
`
	os.WriteFile(".env", []byte(content), 0644)
	log.Println("Created default .env file. Please update with your settings.")
} 