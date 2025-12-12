package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	_ "modernc.org/sqlite"
)

// Test Cases cho Xác thực người dùng

// KIỂM TRA ĐĂNG KÝ THÀNH CÔNG
func TestRegisterSuccess(t *testing.T) {
	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	payload := map[string]interface{}{
		"username":   "testuser",
		"password":   "Test@123456",
		"public_key": []byte("test_public_key"),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	resp, err := http.Post(ctx.Server.URL+"/register", "application/json", bytes.NewBuffer(body))
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
	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	// Đăng ký lần 1
	payload := map[string]interface{}{
		"username":   "testuser",
		"password":   "Test@123456",
		"public_key": []byte("test_public_key"),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	resp1, err := http.Post(ctx.Server.URL+"/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	resp1.Body.Close()

	// Đăng ký lần 2 với cùng username
	resp2, err := http.Post(ctx.Server.URL+"/register", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("Expected status %d, got %d", http.StatusConflict, resp2.StatusCode)
	}
}

// TestRegisterInvalidJSON kiểm tra đăng ký với JSON không hợp lệ
func TestRegisterInvalidJSON(t *testing.T) {
	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	invalidJSON := []byte(`{"username": "testuser", "password": invalid}`)
	resp, err := http.Post(ctx.Server.URL+"/register", "application/json", bytes.NewBuffer(invalidJSON))
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
	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	// Tạo user trước
	createTestUser(t, ctx.Server, "loginuser", "Password123!")

	// Đăng nhập
	payload := map[string]interface{}{
		"username": "loginuser",
		"password": "Password123!",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal login payload: %v", err)
	}

	resp, err := http.Post(ctx.Server.URL+"/login", "application/json", bytes.NewBuffer(body))
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

	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	// Tạo user
	createTestUser(t, ctx.Server, "validuser", "Password123!")

	tests := []struct {
		name     string
		username string
		password string
	}{
		{"Wrong password", "validuser", "WrongPass123!"},
		{"Non-existent user", "nonexistent", "Password123!"},
		{"Empty password", "validuser", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]interface{}{
				"username": tt.username,
				"password": tt.password,
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("Failed to marshal payload: %v", err)
			}

			resp, err := http.Post(ctx.Server.URL+"/login", "application/json", bytes.NewBuffer(body))
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("Expected status 401, got %d", resp.StatusCode)
			}
		})
	}
}

// TestPasswordHashingInDatabase kiểm tra mật khẩu được hash trong database
func TestPasswordHashingInDatabase(t *testing.T) {

	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	password := "MySecure123!"
	createTestUser(t, ctx.Server, "hashuser", password)

	// Kiểm tra password trong DB không phải plaintext
	var storedPassword string
	err := ctx.DB.QueryRow("SELECT password_hash FROM users WHERE username = ?", "hashuser").Scan(&storedPassword)
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

	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	// Tạo user và note
	token := createTestUser(t, ctx.Server, "tokenuser", "Password123!")

	notePayload := map[string]interface{}{
		"content": base64.StdEncoding.EncodeToString([]byte("Test note content")),
		"shared_keys": map[string][]byte{
			"tokenuser": []byte("dummy_key"),
		},
	}
	noteBody, err := json.Marshal(notePayload)
	if err != nil {
		t.Fatalf("Failed to marshal note payload: %v", err)
	}

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
			req, _ := http.NewRequest("POST", ctx.Server.URL+"/notes", bytes.NewBuffer(noteBody))
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
	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			payload := map[string]interface{}{
				"username":   "user" + string(rune('0'+id)),
				"password":   "Password123!",
				"public_key": []byte("test_key"),
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Errorf("Failed to marshal payload for user %d: %v", id, err)
				done <- true
				return
			}

			resp, err := http.Post(ctx.Server.URL+"/register", "application/json", bytes.NewBuffer(body))
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
