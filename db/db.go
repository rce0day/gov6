package db

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"ipv6-proxy/config"
	"crypto/sha256"
	"crypto/subtle"
)

type User struct {
	ID          int
	Username    string
	Password    string // stored as sha256 hash
	ThreadLimit int
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ExpiresAt   *time.Time // when the user account expires, nil means never
}

type Admin struct {
	ID        int
	APIKey    string
	CreatedAt time.Time
}

type Request struct {
	Username  string
	Timestamp time.Time
}

type DB struct {
	db               *sql.DB
	Config           *config.Config
	Users            map[string]User
	RequestsMap      map[string][]time.Time
	mutex            sync.RWMutex
	requestsMutex    sync.RWMutex
	refreshTicker    *time.Ticker
	cleanupTicker    *time.Ticker
	LastRefreshedAt  time.Time
}

func NewDB(cfg *config.Config) (*DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("error connecting to database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("error pinging database: %v", err)
	}

	database := &DB{
		db:           db,
		Config:       cfg,
		Users:        make(map[string]User),
		RequestsMap:  make(map[string][]time.Time),
		LastRefreshedAt: time.Now(),
	}

	err = database.InitDB()
	if err != nil {
		return nil, err
	}

	err = database.RefreshUsers()
	if err != nil {
		log.Printf("Warning: Failed to load initial user data: %v", err)
	}

	database.StartBackgroundRefresh()

	database.StartRequestCleanup()

	return database, nil
}

func (d *DB) InitDB() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL UNIQUE,
			password VARCHAR(64) NOT NULL,
			thread_limit INT NOT NULL DEFAULT 100,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NULL DEFAULT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("error creating users table: %v", err)
	}

	_, err = d.db.Exec(`
		ALTER TABLE users
		ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP NULL DEFAULT NULL
	`)

	_, err = d.db.Exec(`
		CREATE TABLE IF NOT EXISTS admins (
			id INT AUTO_INCREMENT PRIMARY KEY,
			api_key VARCHAR(64) NOT NULL UNIQUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("error creating admins table: %v", err)
	}

	var count int
	err = d.db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	if err != nil {
		return fmt.Errorf("error checking admin count: %v", err)
	}

	if count == 0 {
		_, err = d.db.Exec("INSERT INTO admins (api_key) VALUES (?)", d.Config.AdminAPIKey)
		if err != nil {
			return fmt.Errorf("error creating default admin: %v", err)
		}
		log.Println("Created default admin with API key from configuration")
	}

	err = d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return fmt.Errorf("error checking user count: %v", err)
	}

	if count == 0 {
		_, err = d.db.Exec(
			"INSERT INTO users (username, password, thread_limit, expires_at) VALUES (?, ?, ?, NULL)",
			"admin",
			"make sure im sha256!", // random sha256 hash
			d.Config.DefaultThreadLimit,
		)
		if err != nil {
			return fmt.Errorf("error creating default user: %v", err)
		}
		log.Println("Created default user 'admin' with password 'make sure im sha256!'")
	}

	return nil
}

func (d *DB) RefreshUsers() error {
	rows, err := d.db.Query(`
		SELECT id, username, password, thread_limit, created_at, updated_at, expires_at 
		FROM users
		WHERE expires_at IS NULL OR expires_at > NOW()
	`)
	if err != nil {
		return fmt.Errorf("error querying users: %v", err)
	}
	defer rows.Close()

	newUsers := make(map[string]User)

	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.ThreadLimit, &user.CreatedAt, &user.UpdatedAt, &user.ExpiresAt)
		if err != nil {
			return fmt.Errorf("error scanning user row: %v", err)
		}
		newUsers[user.Username] = user
	}

	d.mutex.Lock()
	d.Users = newUsers
	d.LastRefreshedAt = time.Now()
	d.mutex.Unlock()

	log.Printf("Refreshed user data, loaded %d active users", len(newUsers))
	return nil
}

func (d *DB) StartBackgroundRefresh() {
	d.refreshTicker = time.NewTicker(d.Config.DBRefreshInterval)
	
	go func() {
		for range d.refreshTicker.C {
			err := d.RefreshUsers()
			if err != nil {
				log.Printf("Error refreshing users: %v", err)
			}
		}
	}()
	
	log.Printf("Started background refresh with interval: %v", d.Config.DBRefreshInterval)
}

func (d *DB) StartRequestCleanup() {
	d.cleanupTicker = time.NewTicker(1 * time.Minute)
	
	go func() {
		for range d.cleanupTicker.C {
			d.CleanupOldRequests()
		}
	}()
	
	log.Println("Started request cleanup routine")
}

func (d *DB) CleanupOldRequests() {
	cutoff := time.Now().Add(-1 * time.Minute)
	
	d.requestsMutex.Lock()
	defer d.requestsMutex.Unlock()
	
	for username, timestamps := range d.RequestsMap {
		var newTimestamps []time.Time
		for _, ts := range timestamps {
			if ts.After(cutoff) {
				newTimestamps = append(newTimestamps, ts)
			}
		}
		
		if len(newTimestamps) > 0 {
			d.RequestsMap[username] = newTimestamps
		} else {
			delete(d.RequestsMap, username)
		}
	}
	
	log.Printf("[THREADS] Cleaned up request tracking - current map size: %d", len(d.RequestsMap))
}

func (d *DB) AddRequest(username string) {
	d.requestsMutex.Lock()
	defer d.requestsMutex.Unlock()
	
	d.RequestsMap[username] = append(d.RequestsMap[username], time.Now())
}

func (d *DB) CanMakeRequest(username string) bool {
	d.mutex.RLock()
	user, exists := d.Users[username]
	d.mutex.RUnlock()
	
	if !exists {
		log.Printf("[THREADS] User not found: %s", username)
		return false
	}
	
	d.requestsMutex.RLock()
	defer d.requestsMutex.RUnlock()
	
	oneSecondAgo := time.Now().Add(-1 * time.Second)
	recentCount := 0
	
	timestamps, exists := d.RequestsMap[username]
	if !exists {
		return true
	}
	
	for _, ts := range timestamps {
		if ts.After(oneSecondAgo) {
			recentCount++
		}
	}
	
	allowed := recentCount < user.ThreadLimit
	if !allowed {
		log.Printf("[THREADS] User %s at limit: %d requests in last second (limit: %d)", 
			username, recentCount, user.ThreadLimit)
	}
	
	return allowed
}

func (d *DB) Close() error {
	if d.refreshTicker != nil {
		d.refreshTicker.Stop()
	}
	
	if d.cleanupTicker != nil {
		d.cleanupTicker.Stop()
	}
	
	return d.db.Close()
}

func (d *DB) GetUser(username string) (User, bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	
	user, exists := d.Users[username]
	if !exists {
		return User{}, false
	}
	
	if user.ExpiresAt != nil && user.ExpiresAt.Before(time.Now()) {
		return User{}, false
	}
	
	return user, true
}

func (d *DB) AddUser(username, passwordHash string, threadLimit int, expiresAt *time.Time) error {
	var err error
	if expiresAt == nil {
		_, err = d.db.Exec(
			"INSERT INTO users (username, password, thread_limit, expires_at) VALUES (?, ?, ?, NULL)",
			username, passwordHash, threadLimit,
		)
	} else {
		_, err = d.db.Exec(
			"INSERT INTO users (username, password, thread_limit, expires_at) VALUES (?, ?, ?, ?)",
			username, passwordHash, threadLimit, expiresAt,
		)
	}
	
	if err != nil {
		return fmt.Errorf("error adding user: %v", err)
	}
	
	return d.RefreshUsers()
}

func (d *DB) UpdateUser(username, passwordHash string, threadLimit int, expiresAt *time.Time) error {
	var err error
	
	if passwordHash == "" {
		if expiresAt == nil {
			_, err = d.db.Exec(
				"UPDATE users SET thread_limit = ?, expires_at = NULL WHERE username = ?",
				threadLimit, username,
			)
		} else {
			_, err = d.db.Exec(
				"UPDATE users SET thread_limit = ?, expires_at = ? WHERE username = ?",
				threadLimit, expiresAt, username,
			)
		}
	} else {
		if expiresAt == nil {
			_, err = d.db.Exec(
				"UPDATE users SET password = ?, thread_limit = ?, expires_at = NULL WHERE username = ?",
				passwordHash, threadLimit, username,
			)
		} else {
			_, err = d.db.Exec(
				"UPDATE users SET password = ?, thread_limit = ?, expires_at = ? WHERE username = ?",
				passwordHash, threadLimit, expiresAt, username,
			)
		}
	}
	
	if err != nil {
		return fmt.Errorf("error updating user: %v", err)
	}
	
	return d.RefreshUsers()
}

func (d *DB) DeleteUser(username string) error {
	_, err := d.db.Exec("DELETE FROM users WHERE username = ?", username)
	if err != nil {
		return fmt.Errorf("error deleting user: %v", err)
	}
	
	d.mutex.Lock()
	delete(d.Users, username)
	d.mutex.Unlock()
	
	d.requestsMutex.Lock()
	delete(d.RequestsMap, username)
	d.requestsMutex.Unlock()
	
	return nil
}

func (d *DB) ValidateAPIKey(apiKey string) bool {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM admins WHERE api_key = ?", apiKey).Scan(&count)
	if err != nil {
		log.Printf("Error validating API key: %v", err)
		return false
	}
	
	return count > 0
}

func (d *DB) GetAllUsers() []User {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	
	users := make([]User, 0, len(d.Users))
	for _, user := range d.Users {
		users = append(users, user)
	}
	
	return users
}

func (d *DB) VerifyPassword(username, password string) bool {
	user, exists := d.GetUser(username)
	if !exists {
		return false
	}
	
	hash := sha256.Sum256([]byte(password))
	calculatedHash := fmt.Sprintf("%x", hash)
	
	log.Printf("[DB] Password verification for user %s", username)
	log.Printf("[DB] Calculated hash: %s", calculatedHash)
	log.Printf("[DB] Stored hash: %s", user.Password) 
	
	return subtle.ConstantTimeCompare([]byte(calculatedHash), []byte(user.Password)) == 1
} 