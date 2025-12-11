package test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

// Unit tests cho các hàm mã hóa

// TestAESEncryptionDecryption kiểm tra mã hóa và giải mã AES-GCM
func TestAESEncryptionDecryption(t *testing.T) {

	// Tạo AES key 256-bit
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	keyHex := hex.EncodeToString(key)

	plaintext := "This is a secret message"

	// Test mã hóa
	block, err := aes.NewCipher(key)
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
	ciphertextHex := hex.EncodeToString(ciphertext)

	// Test giải mã
	ciphertextBytes, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		t.Fatalf("Failed to decode ciphertext: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		t.Fatal("Ciphertext too short")
	}

	nonce2, ciphertextBytes := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce2, ciphertextBytes, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("Expected '%s', got '%s'", plaintext, string(decrypted))
	}

	// Test với key sai
	wrongKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, wrongKey); err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	wrongBlock, _ := aes.NewCipher(wrongKey)
	wrongGcm, _ := cipher.NewGCM(wrongBlock)

	ciphertextBytes2, _ := hex.DecodeString(ciphertextHex)
	nonce3, ciphertextBytes2 := ciphertextBytes2[:nonceSize], ciphertextBytes2[nonceSize:]
	_, err = wrongGcm.Open(nil, nonce3, ciphertextBytes2, nil)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key")
	}

	t.Logf("AES-GCM Encryption/Decryption: OK (Key: %s...)", keyHex[:16])
}

// TestAESKeySize kiểm tra kích thước key
func TestAESKeySize(t *testing.T) {

	tests := []struct {
		name    string
		keySize int
		valid   bool
	}{
		{"128-bit key", 16, true},
		{"192-bit key", 24, true},
		{"256-bit key", 32, true},
		{"Invalid 64-bit key", 8, false},
		{"Invalid 512-bit key", 64, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := aes.NewCipher(key)

			if tt.valid && err != nil {
				t.Errorf("Expected valid key size %d to work, got error: %v", tt.keySize, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("Expected invalid key size %d to fail", tt.keySize)
			}
		})
	}
}

// TestEncryptionUniqueness kiểm tra mỗi lần mã hóa tạo kết quả khác nhau (do nonce random)
func TestEncryptionUniqueness(t *testing.T) {

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := "Test message"
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	// Mã hóa 2 lần
	nonce1 := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce1)
	ciphertext1 := gcm.Seal(nonce1, nonce1, []byte(plaintext), nil)

	nonce2 := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce2)
	ciphertext2 := gcm.Seal(nonce2, nonce2, []byte(plaintext), nil)

	if hex.EncodeToString(ciphertext1) == hex.EncodeToString(ciphertext2) {
		t.Error("Two encryptions of same plaintext should produce different ciphertexts")
	}

	// Cả hai phải giải mã thành cùng plaintext
	_, ct1 := ciphertext1[:gcm.NonceSize()], ciphertext1[gcm.NonceSize():]
	decrypted1, _ := gcm.Open(nil, nonce1, ct1, nil)

	_, ct2 := ciphertext2[:gcm.NonceSize()], ciphertext2[gcm.NonceSize():]
	decrypted2, _ := gcm.Open(nil, nonce2, ct2, nil)

	if string(decrypted1) != plaintext || string(decrypted2) != plaintext {
		t.Error("Decryption failed for both ciphertexts")
	}
}

// BenchmarkAESEncryption đo performance mã hóa AES
func BenchmarkAESEncryption(b *testing.B) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	plaintext := []byte("This is a benchmark test message for AES encryption")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nonce := make([]byte, gcm.NonceSize())
		io.ReadFull(rand.Reader, nonce)
		_ = gcm.Seal(nonce, nonce, plaintext, nil)
	}
}

// BenchmarkAESDecryption đo performance giải mã AES
func BenchmarkAESDecryption(b *testing.B) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	plaintext := []byte("This is a benchmark test message for AES decryption")
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nonceSize := gcm.NonceSize()
		nonce2, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
		_, _ = gcm.Open(nil, nonce2, ct, nil)
	}
}
