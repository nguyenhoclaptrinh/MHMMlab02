package test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"lab02/pkg/server/handlers"

	_ "modernc.org/sqlite"
)

// TestContext chứa tất cả dependencies cho mỗi test (isolated)
type TestContext struct {
	Server *httptest.Server
	DB     *sql.DB
	DBPath string
}

// setupTestServer tạo isolated test context cho mỗi test
func setupTestServer(t testing.TB) *TestContext {
	t.Helper()

	// Tạo temp directory cho database (auto cleanup)
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Tạo schema (reuse từ production nếu có migration)
	schema := `
	CREATE TABLE users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		salt TEXT NOT NULL,
		public_key BLOB
	);

	CREATE TABLE notes (
		id TEXT PRIMARY KEY,
		owner_id TEXT NOT NULL,
		content TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		expires_at DATETIME,
		share_token TEXT,
		title TEXT,
		filename TEXT,
		file_content TEXT,
		encrypted BOOLEAN DEFAULT 1
	);

	CREATE INDEX idx_notes_owner ON notes(owner_id);

	CREATE TABLE shared_keys (
		note_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		encrypted_key TEXT NOT NULL,
		PRIMARY KEY (note_id, user_id)
	);

	CREATE INDEX idx_shared_keys_user ON shared_keys(user_id);

	CREATE TABLE share_links (
		token TEXT PRIMARY KEY,
		note_id TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		expires_at DATETIME,
		max_visits INTEGER,
		visit_count INTEGER DEFAULT 0
	);
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	// Tạo HTTP routes với real handlers
	server := handlers.NewServer(db)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	return &TestContext{
		Server: httptest.NewServer(mux),
		DB:     db,
		DBPath: dbPath,
	}
}

// Cleanup đóng tất cả resources
func (ctx *TestContext) Cleanup() {
	if ctx.Server != nil {
		ctx.Server.Close()
	}
	if ctx.DB != nil {
		ctx.DB.Close()
	}
	// TempDir tự động cleanup bởi testing framework
}

// cleanupTestData - deprecated, dùng ctx.Cleanup() thay thế
func cleanupTestData(t testing.TB) {
	// Backward compatibility - no-op vì TempDir tự cleanup
}

// createTestUser helper để tạo user và trả về token
func createTestUser(t testing.TB, server *httptest.Server, username, password string) string {
	// Register via real HTTP
	regPayload := map[string]interface{}{
		"username":   username,
		"password":   password,
		"public_key": []byte("test_public_key_" + username),
	}
	regBody, _ := json.Marshal(regPayload)

	resp, err := http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(regBody))
	if err != nil {
		t.Fatalf("Failed to register user %s: %v", username, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create test user %s: status %d", username, resp.StatusCode)
	}

	// Login to get token
	loginPayload := map[string]interface{}{
		"username": username,
		"password": password,
	}
	loginBody, _ := json.Marshal(loginPayload)

	loginResp, err := http.Post(server.URL+"/login", "application/json", bytes.NewBuffer(loginBody))
	if err != nil {
		t.Fatalf("Failed to login user %s: %v", username, err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to login test user %s: status %d", username, loginResp.StatusCode)
	}

	var response map[string]interface{}
	json.NewDecoder(loginResp.Body).Decode(&response)
	return response["token"].(string)
}

// createTestUserWithRetry tạo user với retry logic để tránh SQLite lock
func createTestUserWithRetry(t testing.TB, server *httptest.Server, username, password string) string {
	maxRetries := 3
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 50ms, 100ms, 200ms
			time.Sleep(time.Duration(50*(1<<uint(attempt-1))) * time.Millisecond)
		}

		// Register via real HTTP
		regPayload := map[string]interface{}{
			"username":   username,
			"password":   password,
			"public_key": []byte("test_public_key_" + username),
		}
		regBody, _ := json.Marshal(regPayload)

		resp, err := http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(regBody))
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		}

		// Login to get token
		loginPayload := map[string]interface{}{
			"username": username,
			"password": password,
		}
		loginBody, _ := json.Marshal(loginPayload)

		loginResp, err := http.Post(server.URL+"/login", "application/json", bytes.NewBuffer(loginBody))
		if err != nil {
			lastErr = err
			continue
		}
		defer loginResp.Body.Close()

		if loginResp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("login status %d", loginResp.StatusCode)
			continue
		}

		var response map[string]interface{}
		json.NewDecoder(loginResp.Body).Decode(&response)
		return response["token"].(string)
	}

	t.Fatalf("Failed to create user %s after %d attempts: %v", username, maxRetries, lastErr)
	return ""
}
