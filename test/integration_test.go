package test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

// Integration và Performance Tests

// TestFullUserWorkflow kiểm tra workflow hoàn chỉnh
func TestFullUserWorkflow(t *testing.T) {
	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	// 1. Register
	regPayload := map[string]interface{}{
		"username":   "fullworkflowuser",
		"password":   "SecurePass123!",
		"public_key": []byte("test_public_key"),
	}
	regBody, _ := json.Marshal(regPayload)

	resp, err := http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(regBody))
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d", resp.StatusCode)
	}

	// 2. Login
	loginPayload := map[string]interface{}{
		"username": "fullworkflowuser",
		"password": "SecurePass123!",
	}
	loginBody, _ := json.Marshal(loginPayload)

	loginResp, err := http.Post(server.URL+"/login", "application/json", bytes.NewBuffer(loginBody))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	defer loginResp.Body.Close()

	var loginData map[string]interface{}
	json.NewDecoder(loginResp.Body).Decode(&loginData)
	token := loginData["token"].(string)

	// 3. Create encrypted note
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	plaintext := "My secure note"
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	notePayload := map[string]interface{}{
		"content": base64.StdEncoding.EncodeToString(ciphertext),
		"shared_keys": map[string][]byte{
			"fullworkflowuser": key,
		},
	}
	noteBody, _ := json.Marshal(notePayload)

	client := &http.Client{}
	noteReq, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	noteReq.Header.Set("Content-Type", "application/json")
	noteReq.Header.Set("Authorization", "Bearer "+token)

	noteResp, err := client.Do(noteReq)
	if err != nil {
		t.Fatalf("Create note failed: %v", err)
	}
	defer noteResp.Body.Close()

	var noteData map[string]interface{}
	json.NewDecoder(noteResp.Body).Decode(&noteData)
	noteID := noteData["id"].(string)

	// 4. Retrieve and decrypt note
	getReq, _ := http.NewRequest("GET", server.URL+"/notes/"+noteID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Get note failed: %v", err)
	}
	defer getResp.Body.Close()

	var retrievedNote map[string]interface{}
	json.NewDecoder(getResp.Body).Decode(&retrievedNote)

	encryptedContent := retrievedNote["content"].(string)
	ciphertextBytes, _ := base64.StdEncoding.DecodeString(encryptedContent)
	nonceSize := gcm.NonceSize()
	nonce2, ct := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
	decrypted, _ := gcm.Open(nil, nonce2, ct, nil)

	if string(decrypted) != plaintext {
		t.Errorf("Expected '%s', got '%s'", plaintext, string(decrypted))
	}

	t.Logf("Full Workflow: ✅ Register → Login → Create Note → Retrieve Note → Decrypt")
}

// TestConcurrentNoteCreation kiểm tra tạo notes đồng thời
func TestConcurrentNoteCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent test in short mode")
	}
	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	token := createTestUser(t, server, "concurrentuser", "Password123!")

	var wg sync.WaitGroup
	numNotes := 5
	errors := make(chan error, numNotes)

	for i := 0; i < numNotes; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			notePayload := map[string]interface{}{
				"content": base64.StdEncoding.EncodeToString([]byte("Note " + string(rune('0'+id)))),
				"shared_keys": map[string][]byte{
					"concurrentuser": []byte("dummy_key"),
				},
			}
			noteBody, _ := json.Marshal(notePayload)

			client := &http.Client{}
			req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := client.Do(req)
			if err != nil {
				errors <- err
				return
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("status code %d", resp.StatusCode)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	errorCount := 0
	for err := range errors {
		if err != nil {
			errorCount++
			t.Logf("Error: %v", err)
		}
	}

	if errorCount > 0 {
		t.Errorf("Failed %d out of %d concurrent note creations", errorCount, numNotes)
	} else {
		t.Logf("Concurrent Creation: ✅ All %d notes created successfully", numNotes)
	}
}

// TestStressMultipleUsers kiểm tra nhiều users cùng lúc
func TestStressMultipleUsers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	numUsers := 2
	notesPerUser := 2

	// Tạo users tuần tự để tránh SQLite database lock
	users := make([]string, numUsers)
	for i := 0; i < numUsers; i++ {
		username := "stressuser" + string(rune('0'+i))
		token := createTestUserWithRetry(t, server, username, "Password123!")
		users[i] = token
	}

	// Sau đó mỗi user tạo notes song song
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(userIndex int, token string) {
			defer wg.Done()

			for j := 0; j < notesPerUser; j++ {
				notePayload := map[string]interface{}{
					"content": base64.StdEncoding.EncodeToString([]byte("Note " + string(rune('0'+j)) + " from user " + string(rune('0'+userIndex)))),
					"shared_keys": map[string][]byte{
						"stressuser" + string(rune('0'+userIndex)): []byte("dummy_key"),
					},
				}
				noteBody, _ := json.Marshal(notePayload)

				client := &http.Client{}
				req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+token)

				resp, err := client.Do(req)
				if err == nil && (resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK) {
					mu.Lock()
					successCount++
					mu.Unlock()
					resp.Body.Close()
				} else {
					if err != nil {
						t.Logf("Request failed: %v", err)
					} else {
						body, _ := io.ReadAll(resp.Body)
						t.Logf("Request failed with status %d: %s", resp.StatusCode, string(body))
						resp.Body.Close()
					}
				}
			}
		}(i, users[i])
	}

	wg.Wait()

	expectedNotes := numUsers * notesPerUser
	if successCount < expectedNotes {
		t.Logf("Stress Test: Created %d/%d notes successfully", successCount, expectedNotes)
	} else {
		t.Logf("Stress Test: %d users created %d notes each (%d total)", numUsers, notesPerUser, successCount)
	}

	// Pass test nếu ít nhất 90% notes được tạo thành công
	if successCount < int(float64(expectedNotes)*0.9) {
		t.Errorf("Only %d/%d notes created (expected at least 90%%)", successCount, expectedNotes)
	}
}

// BenchmarkRegisterUser đo performance đăng ký
func BenchmarkRegisterUser(b *testing.B) {
	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payload := map[string]interface{}{
			"username":   "benchuser" + string(rune('0'+i%10)),
			"password":   "Password123!",
			"public_key": []byte("test_key"),
		}
		body, _ := json.Marshal(payload)

		http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(body))
	}
}

// BenchmarkLoginUser đo performance đăng nhập
func BenchmarkLoginUser(b *testing.B) {
	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(nil)

	// Tạo test user trước
	regPayload := map[string]interface{}{
		"username":   "benchloginuser",
		"password":   "Password123!",
		"public_key": []byte("test_key"),
	}
	regBody, _ := json.Marshal(regPayload)
	http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(regBody))

	loginPayload := map[string]interface{}{
		"username": "benchloginuser",
		"password": "Password123!",
	}
	loginBody, _ := json.Marshal(loginPayload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, _ := http.Post(server.URL+"/login", "application/json", bytes.NewBuffer(loginBody))
		if resp != nil {
			resp.Body.Close()
		}
	}
}

// BenchmarkCreateNote đo performance tạo note
func BenchmarkCreateNote(b *testing.B) {
	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(nil)

	// Setup user
	regPayload := map[string]interface{}{
		"username":   "benchnoteuser",
		"password":   "Password123!",
		"public_key": []byte("test_key"),
	}
	regBody, _ := json.Marshal(regPayload)
	http.Post(server.URL+"/register", "application/json", bytes.NewBuffer(regBody))

	loginPayload := map[string]interface{}{
		"username": "benchnoteuser",
		"password": "Password123!",
	}
	loginBody, _ := json.Marshal(loginPayload)
	loginResp, _ := http.Post(server.URL+"/login", "application/json", bytes.NewBuffer(loginBody))

	var loginData map[string]interface{}
	json.NewDecoder(loginResp.Body).Decode(&loginData)
	loginResp.Body.Close()
	token := loginData["token"].(string)

	notePayload := map[string]interface{}{
		"content": base64.StdEncoding.EncodeToString([]byte("Benchmark note content")),
		"shared_keys": map[string][]byte{
			"benchnoteuser": []byte("dummy_key"),
		},
	}
	noteBody, _ := json.Marshal(notePayload)

	client := &http.Client{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, _ := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
	}
}

// BenchmarkAESEncryptionE2E đo performance E2E encryption
func BenchmarkAESEncryptionE2E(b *testing.B) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	plaintext := []byte("Benchmark encryption data for performance testing")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nonce := make([]byte, gcm.NonceSize())
		io.ReadFull(rand.Reader, nonce)
		_ = gcm.Seal(nonce, nonce, plaintext, nil)
	}
}

// BenchmarkAESDecryptionE2E đo performance E2E decryption
func BenchmarkAESDecryptionE2E(b *testing.B) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	plaintext := []byte("Benchmark decryption data for performance testing")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nonceSize := gcm.NonceSize()
		n, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
		_, _ = gcm.Open(nil, n, ct, nil)
	}
}
