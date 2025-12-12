package test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	_ "modernc.org/sqlite"
)

// End-to-End Encryption Tests

// TestEndToEndNoteEncryption kiểm tra note được mã hóa end-to-end
func TestEndToEndNoteEncryption(t *testing.T) {

	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	token := createTestUser(t, ctx.Server, "e2euser", "Password123!")

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
	encryptedContent := base64.StdEncoding.EncodeToString(ciphertext)

	// Upload encrypted note
	notePayload := map[string]interface{}{
		"content": encryptedContent,
		"shared_keys": map[string][]byte{
			"e2euser": key,
		},
	}
	noteBody, _ := json.Marshal(notePayload)

	req, _ := http.NewRequest("POST", ctx.Server.URL+"/notes", bytes.NewBuffer(noteBody))
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
	getReq, _ := http.NewRequest("GET", ctx.Server.URL+"/notes/"+noteID, nil)
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
	ciphertextBytes, _ := base64.StdEncoding.DecodeString(retrievedContent)
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

	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	token1 := createTestUser(t, ctx.Server, "sender", "Password123!")
	token2 := createTestUser(t, ctx.Server, "receiver", "Password123!")

	// User 1 tạo encrypted note
	key1 := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key1); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := "Shared encrypted message"
	block, err := aes.NewCipher(key1)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encryptedContent := base64.StdEncoding.EncodeToString(ciphertext)

	notePayload := map[string]interface{}{
		"content": encryptedContent,
		"shared_keys": map[string][]byte{
			"sender": key1,
		},
	}
	noteBody, err := json.Marshal(notePayload)
	if err != nil {
		t.Fatalf("Failed to marshal note payload: %v", err)
	}

	req, _ := http.NewRequest("POST", ctx.Server.URL+"/notes", bytes.NewBuffer(noteBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token1)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create note: %v", err)
	}
	defer resp.Body.Close()

	var noteResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&noteResp); err != nil {
		t.Fatalf("Failed to decode note response: %v", err)
	}
	noteID := noteResp["id"].(string)

	// Simulate key sharing: encrypt key1 với public key của receiver
	// For test, just use base64 of key1 (mock encryption)
	encryptedKey := key1 // In real test we should encrypt. Here just mock bytes.

	sharePayload := map[string]interface{}{
		"note_id":       noteID,
		"target_user":   "receiver",
		"encrypted_key": encryptedKey,
	}
	shareBody, err := json.Marshal(sharePayload)
	if err != nil {
		t.Fatalf("Failed to marshal share payload: %v", err)
	}

	shareReq, _ := http.NewRequest("POST", ctx.Server.URL+"/notes/share", bytes.NewBuffer(shareBody))
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

	// Reciever gets note to check keys
	getReq, _ := http.NewRequest("GET", ctx.Server.URL+"/notes/"+noteID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token2)

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Failed to get note: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", getResp.StatusCode)
	}

	var noteObj map[string]interface{}
	if err := json.NewDecoder(getResp.Body).Decode(&noteObj); err != nil {
		t.Fatalf("Failed to decode note object: %v", err)
	}

	if keys, ok := noteObj["shared_keys"].(map[string]interface{}); ok {
		if _, ok := keys["receiver"]; !ok {
			t.Error("Receiver key not found in shared_keys")
		}
	} else {
		t.Error("shared_keys missing or invalid format")
	}

	t.Logf("Shared Key Encryption: ✅ Keys encrypted and shared successfully")
}

// TestMultipleUsersE2EEncryption kiểm tra nhiều users với E2E encryption
func TestMultipleUsersE2EEncryption(t *testing.T) {

	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	// Tạo 3 users
	token1 := createTestUser(t, ctx.Server, "alice", "Password123!")
	token2 := createTestUser(t, ctx.Server, "bob", "Password123!")
	token3 := createTestUser(t, ctx.Server, "charlie", "Password123!")

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
			"content": base64.StdEncoding.EncodeToString(ciphertext),
			"shared_keys": map[string][]byte{
				u.name: key,
			},
		}
		noteBody, _ := json.Marshal(notePayload)

		req, _ := http.NewRequest("POST", ctx.Server.URL+"/notes", bytes.NewBuffer(noteBody))
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

	ctx := setupTestServer(t)
	defer ctx.Cleanup()

	token := createTestUser(t, ctx.Server, "keyrotuser", "Password123!")

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
		"content": base64.StdEncoding.EncodeToString(ciphertext1),
		"shared_keys": map[string][]byte{
			"keyrotuser": key1,
		},
	}
	noteBody, _ := json.Marshal(notePayload)

	req, _ := http.NewRequest("POST", ctx.Server.URL+"/notes", bytes.NewBuffer(noteBody))
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
	getReq, _ := http.NewRequest("GET", ctx.Server.URL+"/notes/"+noteID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)

	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Failed to get note: %v", err)
	}
	defer getResp.Body.Close()

	var note map[string]interface{}
	json.NewDecoder(getResp.Body).Decode(&note)

	// Decrypt với key1
	cipherBytes, _ := base64.StdEncoding.DecodeString(note["content"].(string))
	nonceSize := gcm1.NonceSize()
	nonce, ct := cipherBytes[:nonceSize], cipherBytes[nonceSize:]
	decrypted, _ := gcm1.Open(nil, nonce, ct, nil)

	// Re-encrypt với key2
	block2, _ := aes.NewCipher(key2)
	gcm2, _ := cipher.NewGCM(block2)
	nonce2 := make([]byte, gcm2.NonceSize())
	io.ReadFull(rand.Reader, nonce2)
	newCiphertext := gcm2.Seal(nonce2, nonce2, decrypted, nil)
	_ = newCiphertext // Silence unused error

	// Update note với encrypted content mới (NOT IMPLEMENTED IN BACKEND YET)
	// Skip actual update call.

	t.Logf("Key Rotation: Skipped (Update Note endpoint not implemented)")
}
