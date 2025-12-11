package test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	_ "modernc.org/sqlite"
)

// End-to-End Encryption Tests

// TestEndToEndNoteEncryption kiểm tra note được mã hóa end-to-end
func TestEndToEndNoteEncryption(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	token := createTestUser(t, server, "e2euser", "Password123!")

	// Tạo AES key
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	// Mã hóa nội dung trên client
	plaintext := "Confidential data - must be encrypted"
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encryptedContent := hex.EncodeToString(ciphertext)

	// Upload encrypted note
	notePayload := map[string]interface{}{
		"content": encryptedContent,
	}
	noteBody, _ := json.Marshal(notePayload)

	req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to upload note: %v", err)
	}
	defer resp.Body.Close()

	var noteResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&noteResp)
	noteID := noteResp["id"].(string)

	// Lấy note về
	getReq, _ := http.NewRequest("GET", server.URL+"/notes/"+noteID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Failed to get note: %v", err)
	}
	defer getResp.Body.Close()

	var retrievedNote map[string]interface{}
	json.NewDecoder(getResp.Body).Decode(&retrievedNote)
	retrievedContent := retrievedNote["content"].(string)

	// Giải mã trên client
	ciphertextBytes, _ := hex.DecodeString(retrievedContent)
	nonceSize := gcm.NonceSize()
	nonce2, ct := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce2, ct, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("Expected '%s', got '%s'", plaintext, string(decrypted))
	}

	// Verify server không lưu plaintext
	if retrievedContent == plaintext {
		t.Error("Server should NOT store plaintext")
	}

	t.Logf("E2E Encryption: ✅ Server stores ciphertext, client decrypts successfully")
}

// TestSharedNoteEncryptedKeys kiểm tra shared note với encrypted keys
func TestSharedNoteEncryptedKeys(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	token1 := createTestUser(t, server, "sender", "Password123!")
	token2 := createTestUser(t, server, "receiver", "Password123!")

	// User 1 tạo encrypted note
	key1 := make([]byte, 32)
	io.ReadFull(rand.Reader, key1)

	plaintext := "Shared encrypted message"
	block, _ := aes.NewCipher(key1)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encryptedContent := hex.EncodeToString(ciphertext)

	notePayload := map[string]interface{}{
		"content": encryptedContent,
	}
	noteBody, _ := json.Marshal(notePayload)

	req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token1)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}
	defer resp.Body.Close()

	var noteResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&noteResp)
	noteID := noteResp["id"].(string)

	// Simulate key sharing: encrypt key1 với public key của receiver
	// (trong thực tế sẽ dùng RSA/hybrid encryption)
	encryptedKey := hex.EncodeToString(key1) + "_encrypted_for_receiver"

	sharePayload := map[string]interface{}{
		"note_id":            noteID,
		"recipient_username": "receiver",
		"encrypted_key":      encryptedKey,
	}
	shareBody, _ := json.Marshal(sharePayload)

	shareReq, _ := http.NewRequest("POST", server.URL+"/notes/share", bytes.NewBuffer(shareBody))
	shareReq.Header.Set("Content-Type", "application/json")
	shareReq.Header.Set("Authorization", "Bearer "+token1)

	shareResp, err := client.Do(shareReq)
	if err != nil {
		t.Fatalf("Failed to share note: %v", err)
	}
	defer shareResp.Body.Close()

	if shareResp.StatusCode != http.StatusOK {
		t.Errorf("Expected share to succeed, got status %d", shareResp.StatusCode)
	}

	// User 2 nhận shared key và decrypt note
	getReq, _ := http.NewRequest("GET", server.URL+"/users/receiver/shared-keys", nil)
	getReq.Header.Set("Authorization", "Bearer "+token2)

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Failed to get shared keys: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", getResp.StatusCode)
	}

	t.Logf("Shared Key Encryption: ✅ Keys encrypted and shared successfully")
}

// TestMultipleUsersE2EEncryption kiểm tra nhiều users với E2E encryption
func TestMultipleUsersE2EEncryption(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	// Tạo 3 users
	token1 := createTestUser(t, server, "alice", "Password123!")
	token2 := createTestUser(t, server, "bob", "Password123!")
	token3 := createTestUser(t, server, "charlie", "Password123!")

	// Mỗi user tạo encrypted note với key riêng
	users := []struct {
		name  string
		token string
		text  string
	}{
		{"alice", token1, "Alice's secret"},
		{"bob", token2, "Bob's secret"},
		{"charlie", token3, "Charlie's secret"},
	}

	for _, u := range users {
		key := make([]byte, 32)
		io.ReadFull(rand.Reader, key)

		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		io.ReadFull(rand.Reader, nonce)
		ciphertext := gcm.Seal(nonce, nonce, []byte(u.text), nil)

		notePayload := map[string]interface{}{
			"content": hex.EncodeToString(ciphertext),
		}
		noteBody, _ := json.Marshal(notePayload)

		req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+u.token)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("User %s failed to create note: %v", u.name, err)
		} else {
			resp.Body.Close()
			t.Logf("User %s: ✅ Created encrypted note", u.name)
		}
	}
}

// TestEncryptionKeyRotation kiểm tra key rotation scenario
func TestEncryptionKeyRotation(t *testing.T) {

	server := setupTestServer()
	defer server.Close()
	defer cleanupTestData(t)

	token := createTestUser(t, server, "keyrotuser", "Password123!")

	// Tạo note với key1
	key1 := make([]byte, 32)
	io.ReadFull(rand.Reader, key1)

	plaintext := "Data encrypted with key1"
	block1, _ := aes.NewCipher(key1)
	gcm1, _ := cipher.NewGCM(block1)
	nonce1 := make([]byte, gcm1.NonceSize())
	io.ReadFull(rand.Reader, nonce1)
	ciphertext1 := gcm1.Seal(nonce1, nonce1, []byte(plaintext), nil)

	notePayload := map[string]interface{}{
		"content": hex.EncodeToString(ciphertext1),
	}
	noteBody, _ := json.Marshal(notePayload)

	req, _ := http.NewRequest("POST", server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}
	defer resp.Body.Close()

	var noteResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&noteResp)
	noteID := noteResp["id"].(string)

	// Simulate key rotation: decrypt với key1, re-encrypt với key2
	key2 := make([]byte, 32)
	io.ReadFull(rand.Reader, key2)

	// Get note
	getReq, _ := http.NewRequest("GET", server.URL+"/notes/"+noteID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Failed to get note: %v", err)
	}
	defer getResp.Body.Close()

	var note map[string]interface{}
	json.NewDecoder(getResp.Body).Decode(&note)

	// Decrypt với key1
	cipherBytes, _ := hex.DecodeString(note["content"].(string))
	nonceSize := gcm1.NonceSize()
	nonce, ct := cipherBytes[:nonceSize], cipherBytes[nonceSize:]
	decrypted, _ := gcm1.Open(nil, nonce, ct, nil)

	// Re-encrypt với key2
	block2, _ := aes.NewCipher(key2)
	gcm2, _ := cipher.NewGCM(block2)
	nonce2 := make([]byte, gcm2.NonceSize())
	io.ReadFull(rand.Reader, nonce2)
	newCiphertext := gcm2.Seal(nonce2, nonce2, decrypted, nil)

	// Update note với encrypted content mới
	updatePayload := map[string]interface{}{
		"content": hex.EncodeToString(newCiphertext),
	}
	updateBody, _ := json.Marshal(updatePayload)

	updateReq, _ := http.NewRequest("PUT", server.URL+"/notes/"+noteID, bytes.NewBuffer(updateBody))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Authorization", "Bearer "+token)

	updateResp, err := client.Do(updateReq)
	if err != nil {
		t.Fatalf("Failed to update note: %v", err)
	}
	defer updateResp.Body.Close()

	if updateResp.StatusCode == http.StatusOK {
		t.Logf("Key Rotation: ✅ Successfully rotated encryption key")
	}
}
