package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"ipv6-proxy/auth"
	"ipv6-proxy/db"
)

type UserAPI struct {
	DB   *db.DB
	Auth *auth.Authenticator
}

func NewUserAPI(database *db.DB, authenticator *auth.Authenticator) *UserAPI {
	return &UserAPI{
		DB:   database,
		Auth: authenticator,
	}
}

func (a *UserAPI) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var userData struct {
			Action      string `json:"action"`
			Username    string `json:"username"`
			Password    string `json:"password"`
			ThreadLimit int    `json:"thread_limit"`
			ExpiresAt   string `json:"expires_at"`
		}

		err := json.NewDecoder(r.Body).Decode(&userData)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if userData.ThreadLimit <= 0 {
			userData.ThreadLimit = a.DB.Config.DefaultThreadLimit
		}

		var expiresAt *time.Time
		if userData.ExpiresAt != "" {
			t, err := parseExpiryDate(userData.ExpiresAt)
			if err != nil {
				http.Error(w, fmt.Sprintf("Invalid expiry date format: %v", err), http.StatusBadRequest)
				return
			}
			expiresAt = &t
		}

		switch userData.Action {
		case "add":
			a.handleAddUser(w, userData.Username, userData.Password, userData.ThreadLimit, expiresAt)

		case "update":
			a.handleUpdateUser(w, userData.Username, userData.Password, userData.ThreadLimit, expiresAt)

		case "delete":
			a.handleDeleteUser(w, userData.Username)

		case "list":
			a.handleListUsers(w)

		default:
			http.Error(w, "Invalid action", http.StatusBadRequest)
		}
	}
}

func parseExpiryDate(dateStr string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err == nil {
		return t, nil
	}

	t, err = time.Parse("2006-01-02", dateStr)
	if err == nil {
		t = time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
		return t, nil
	}

	return time.Time{}, fmt.Errorf("invalid date format, use YYYY-MM-DD or RFC3339")
}

func (a *UserAPI) handleAddUser(w http.ResponseWriter, username, password string, threadLimit int, expiresAt *time.Time) {
	if username == "" || password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	passwordHash := sha256.Sum256([]byte(password))
	passwordHashString := fmt.Sprintf("%x", passwordHash)

	err := a.DB.AddUser(username, passwordHashString, threadLimit, expiresAt)
	if err != nil {
		log.Printf("Error adding user: %v", err)
		http.Error(w, "Failed to add user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User %s added successfully", username)
}

func (a *UserAPI) handleUpdateUser(w http.ResponseWriter, username, password string, threadLimit int, expiresAt *time.Time) {
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	_, exists := a.DB.GetUser(username)
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	passwordHashString := ""
	if password != "" {
		passwordHash := sha256.Sum256([]byte(password))
		passwordHashString = fmt.Sprintf("%x", passwordHash)
	}

	err := a.DB.UpdateUser(username, passwordHashString, threadLimit, expiresAt)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User %s updated successfully", username)
}

func (a *UserAPI) handleDeleteUser(w http.ResponseWriter, username string) {
	if username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	_, exists := a.DB.GetUser(username)
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	err := a.DB.DeleteUser(username)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User %s deleted successfully", username)
}

func (a *UserAPI) handleListUsers(w http.ResponseWriter) {
	users := a.DB.GetAllUsers()

	type UserResponse struct {
		Username    string     `json:"username"`
		ThreadLimit int        `json:"thread_limit"`
		ExpiresAt   *time.Time `json:"expires_at,omitempty"`
		Status      string     `json:"status"`
	}

	response := make([]UserResponse, 0, len(users))
	for _, user := range users {
		status := "active"
		if user.ExpiresAt == nil {
			status = "never expires"
		} else if user.ExpiresAt.Before(time.Now()) {
			status = "expired"
		}

		response = append(response, UserResponse{
			Username:    user.Username,
			ThreadLimit: user.ThreadLimit,
			ExpiresAt:   user.ExpiresAt,
			Status:      status,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
} 