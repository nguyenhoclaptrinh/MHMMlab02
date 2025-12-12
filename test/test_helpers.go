package test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"lab02/pkg/server/handlers"

	_ "modernc.org/sqlite"
)

var testDB *sql.DB
var testDBPath string

// setupTestServer tạo real HTTP test server với router thật
func setupTestServer() *httptest.Server {
	var err error
	// Use file-based DB for better WAL/concurrency support in tests
	// Use file-based DB for better WAL/concurrency support in tests
	testDBPath = fmt.Sprintf("test_%d.db", time.Now().UnixNano())
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(30000)", testDBPath)
	testDB, err = sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatal("Failed to create test database:", err)
	}

	testDB.SetMaxOpenConns(10) // WAL allows concurrent readers

	// Tạo bảng Users
	_, err = testDB.Exec(`CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT,
		salt TEXT,
		public_key BLOB
	)`)
	if err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	// Tạo bảng Notes
	_, err = testDB.Exec(`CREATE TABLE IF NOT EXISTS notes (
		id TEXT PRIMARY KEY,
		owner_id TEXT,
		title TEXT,
		filename TEXT,
		content BLOB,
		encrypted BOOLEAN,
		created_at DATETIME
	)`)
	if err != nil {
		log.Fatal("Failed to create notes table:", err)
	}

	// Index cho notes
	if _, err := testDB.Exec(`CREATE INDEX IF NOT EXISTS idx_notes_owner ON notes(owner_id);`); err != nil {
		log.Fatal("Failed to create index idx_notes_owner:", err)
	}

	// Tạo bảng SharedKeys
	_, err = testDB.Exec(`CREATE TABLE IF NOT EXISTS shared_keys (
		note_id TEXT,
		user_id TEXT,
		encrypted_key BLOB,
		PRIMARY KEY (note_id, user_id)
	)`)
	if err != nil {
		log.Fatal("Failed to create shared_keys table:", err)
	}

	// Index cho shared_keys
	if _, err := testDB.Exec(`CREATE INDEX IF NOT EXISTS idx_shared_keys_user ON shared_keys(user_id);`); err != nil {
		log.Fatal("Failed to create index idx_shared_keys_user:", err)
	}

	// Tạo bảng ShareLinks
	_, err = testDB.Exec(`CREATE TABLE IF NOT EXISTS share_links (
		token TEXT PRIMARY KEY,
		note_id TEXT,
		created_at DATETIME,
		expires_at DATETIME,
		max_visits INTEGER,
		visit_count INTEGER
	)`)
	if err != nil {
		log.Fatal("Failed to create share_links table:", err)
	}

	// Tạo HTTP routes
	mux := http.NewServeMux()
	// Use real handlers to ensure we test the actual logic
	server := handlers.NewServer(testDB)
	server.RegisterRoutes(mux)

	/* Deprecated: Manual test handlers replaced by real handlers
	mux.HandleFunc("/register", handleRegisterTest)
	mux.HandleFunc("/login", handleLoginTest)
	mux.HandleFunc("/notes", handleNotesTest)
	mux.HandleFunc("/notes/", handleNoteDetailTest)
	mux.HandleFunc("/users/", handleGetUserTest)
	mux.HandleFunc("/notes/share", handleShareNoteTest)
	mux.HandleFunc("/notes/share-link", handleGenerateShareLinkTest)
	mux.HandleFunc("/public/notes/", handleGetPublicNoteTest)
	*/

	// Tạo httptest.Server với real HTTP listener
	return httptest.NewServer(mux)
}

// cleanupTestData xóa toàn bộ dữ liệu test
func cleanupTestData(t *testing.T) {
	if testDB != nil {
		testDB.Close()
		os.Remove(testDBPath)
		os.Remove(testDBPath + "-shm")
		os.Remove(testDBPath + "-wal")
	}
}

// createTestUser helper để tạo user và trả về token
func createTestUser(t *testing.T, server *httptest.Server, username, password string) string {
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
func createTestUserWithRetry(t *testing.T, server *httptest.Server, username, password string) string {
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
