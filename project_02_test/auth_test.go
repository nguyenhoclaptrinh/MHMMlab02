package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	_ "modernc.org/sqlite"
)

// Test Cases cho Xác thực người dùng

// KIỂM TRA ĐĂNG KÝ THÀNH CÔNG
func TestRegisterSuccess(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	payload := map[string]interface{}{
		"username":   "testuser",
		"password":   "Test@123456",
		"public_key": []byte("test_public_key"),
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}
}

// TestRegisterDuplicateUsername kiểm tra đăng ký với username đã tồn tại
func TestRegisterDuplicateUsername(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	// Đăng ký lần 1
	payload := map[string]interface{}{
		"username":   "testuser",
		"password":   "Test@123456",
		"public_key": []byte("test_public_key"),
	}
	body, _ := json.Marshal(payload)

	resp1, err := http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	resp1.Body.Close()

	// Đăng ký lần 2 với cùng username
	resp2, err := http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("Expected status %d, got %d", http.StatusConflict, resp2.StatusCode)
	}
}

// TestRegisterWeakPassword kiểm tra đăng ký với mật khẩu yếu
func TestRegisterWeakPassword(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	tests := []struct {
		name     string
		password string
		wantErr  string
	}{
		{"Short password", "Short1!", "Password must be at least 8 characters"},
		{"No uppercase", "lowercase123!", "Password must contain uppercase, lowercase, numbers and special characters"},
		{"No lowercase", "UPPERCASE123!", "Password must contain uppercase, lowercase, numbers and special characters"},
		{"No number", "NoNumberPass!", "Password must contain uppercase, lowercase, numbers and special characters"},
		{"No special", "NoSpecial123", "Password must contain uppercase, lowercase, numbers and special characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]interface{}{
				"username":   "weakuser",
				"password":   tt.password,
				"public_key": []byte("test_key"),
			}
			body, _ := json.Marshal(payload)

			resp, err := http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(body))
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d", resp.StatusCode)
			}

			var response map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&response)
			if response["error"] != tt.wantErr {
				t.Errorf("Expected error '%s', got '%v'", tt.wantErr, response["error"])
			}
		})
	}
}

// TestRegisterInvalidJSON kiểm tra đăng ký với JSON không hợp lệ
func TestRegisterInvalidJSON(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	invalidJSON := []byte(`{"username": "testuser", "password": invalid}`)
	resp, err := http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(invalidJSON))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}
}

// TestLoginSuccess kiểm tra đăng nhập thành công
func TestLoginSuccess(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	// Tạo user trước
	createTestUser(t, server, "loginuser", "Password123!")

	// Đăng nhập
	payload := map[string]interface{}{
		"username": "loginuser",
		"password": "Password123!",
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(server.URL+"/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}

	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)
	if response["token"] == nil {
		t.Error("Expected token in response")
	}
}

// TestLoginInvalidCredentials kiểm tra đăng nhập với thông tin sai
func TestLoginInvalidCredentials(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	// Tạo user
	createTestUser(t, server, "validuser", "Password123!")

	tests := []struct {
		name     string
		username string
		password string
		wantErr  string
	}{
		{"Wrong password", "validuser", "WrongPass123!", "Invalid credentials"},
		{"Non-existent user", "nonexistent", "Password123!", "Invalid credentials"},
		{"Empty password", "validuser", "", "Invalid credentials"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]interface{}{
				"username": tt.username,
				"password": tt.password,
			}
			body, _ := json.Marshal(payload)

			resp, err := http.Post(server.URL+"/login", "application/json", bytes.NewBuffer(body))
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("Expected status 401, got %d", resp.StatusCode)
			}

			var response map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&response)
			if response["error"] != tt.wantErr {
				t.Errorf("Expected error '%s', got '%v'", tt.wantErr, response["error"])
			}
		})
	}
}

// TestPasswordHashingInDatabase kiểm tra mật khẩu được hash trong database
func TestPasswordHashingInDatabase(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	password := "MySecure123!"
	createTestUser(t, server, "hashuser", password)

	// Kiểm tra password trong DB không phải plaintext
	var storedPassword string
	err := testDB.QueryRow("SELECT password_hash FROM users WHERE username = ?", "hashuser").Scan(&storedPassword)
	if err != nil {
		t.Fatalf("Failed to query database: %v", err)
	}

	if storedPassword == password {
		t.Error("Password should be hashed, not stored as plaintext")
	}

	// Password hash phải dài hơn password gốc
	if len(storedPassword) <= len(password) {
		t.Error("Password hash should be longer than original password")
	}
}

// TestInvalidToken kiểm tra token không hợp lệ
func TestInvalidToken(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	// Tạo user và note
	token := createTestUser(t, server, "tokenuser", "Password123!")

	notePayload := map[string]interface{}{
		"content": "Test note content",
	}
	noteBody, _ := json.Marshal(notePayload)

	tests := []struct {
		name  string
		token string
	}{
		{"Invalid token", "invalid.token.here"},
		{"Empty token", ""},
		{"Malformed Bearer", "NotBearer " + token},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
			req.Header.Set("Content-Type", "application/json")
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
				t.Errorf("Expected status 401 or 400, got %d", resp.StatusCode)
			}
		})
	}
}

// TestConcurrentRegistration kiểm tra đăng ký đồng thời
func TestConcurrentRegistration(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			payload := map[string]interface{}{
				"username":   "user" + string(rune('0'+id)),
				"password":   "Password123!",
				"public_key": []byte("test_key"),
			}
			body, _ := json.Marshal(payload)

			resp, err := http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(body))
			if err != nil {
				t.Errorf("Failed to register user %d: %v", id, err)
			} else {
				resp.Body.Close()
			}
			done <- true
		}(i)
	}

	// Đợi tất cả goroutines hoàn thành
	for i := 0; i < 10; i++ {
		<-done
	}
}
