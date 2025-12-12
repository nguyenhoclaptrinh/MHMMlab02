package test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"lab02/pkg/client/crypto"
)

// TestECDHKeyExchange kiểm tra ECDH key exchange thực tế
func TestECDHKeyExchange(t *testing.T) {
	// User A generates keypair
	privA, pubA, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair for User A: %v", err)
	}

	// User B generates keypair
	privB, pubB, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair for User B: %v", err)
	}

	// Both derive shared secret
	secretA, err := crypto.DeriveSharedKey(privA, pubB)
	if err != nil {
		t.Fatalf("User A failed to derive shared key: %v", err)
	}

	secretB, err := crypto.DeriveSharedKey(privB, pubA)
	if err != nil {
		t.Fatalf("User B failed to derive shared key: %v", err)
	}

	// Verify: Shared secrets must match
	if !bytes.Equal(secretA, secretB) {
		t.Error("ECDH shared secrets do not match")
	}

	// Verify key length (should be 32 bytes for AES-256)
	if len(secretA) != 32 {
		t.Errorf("Expected shared key length 32, got %d", len(secretA))
	}

	t.Logf("ECDH Key Exchange: ✅ Shared secrets match (%d bytes)", len(secretA))
}

// TestECDHKeyUniqueness kiểm tra mỗi lần tạo key đều khác nhau
func TestECDHKeyUniqueness(t *testing.T) {
	_, pub1, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate first keypair: %v", err)
	}

	_, pub2, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate second keypair: %v", err)
	}

	if bytes.Equal(pub1, pub2) {
		t.Error("Two generated public keys should be different")
	}
}

// TestECDHInvalidPublicKey kiểm tra xử lý public key không hợp lệ
func TestECDHInvalidPublicKey(t *testing.T) {
	priv, _, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	tests := []struct {
		name   string
		pubKey []byte
	}{
		{"Empty key", []byte{}},
		{"Too short", []byte{1, 2, 3}},
		{"Too long", make([]byte, 64)},
		{"Invalid length", make([]byte, 31)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.DeriveSharedKey(priv, tt.pubKey)
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestAESEncryptDecrypt kiểm tra AES encryption/decryption
func TestAESEncryptDecrypt(t *testing.T) {
	// Generate random key
	key, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	plaintext := []byte("This is a secret message for testing AES-GCM encryption")

	// Encrypt
	ciphertext, err := crypto.EncryptAES(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	// Decrypt
	decrypted, err := crypto.DecryptAES(ciphertext, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify decrypted matches original
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text does not match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// TestAESDecryptWithWrongKey kiểm tra giải mã với sai key
func TestAESDecryptWithWrongKey(t *testing.T) {
	// Generate two different keys
	key1, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate key1: %v", err)
	}

	key2, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate key2: %v", err)
	}

	plaintext := []byte("Secret data")

	// Encrypt with key1
	ciphertext, err := crypto.EncryptAES(plaintext, key1)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Try to decrypt with key2 (wrong key)
	_, err = crypto.DecryptAES(ciphertext, key2)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key, but it succeeded")
	}
}

// TestAESEncryptionUniqueness kiểm tra mỗi lần mã hóa tạo kết quả khác nhau (do nonce)
func TestAESEncryptionUniqueness(t *testing.T) {
	key, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("Same message")

	// Encrypt twice
	ciphertext1, err := crypto.EncryptAES(plaintext, key)
	if err != nil {
		t.Fatalf("Failed first encryption: %v", err)
	}

	ciphertext2, err := crypto.EncryptAES(plaintext, key)
	if err != nil {
		t.Fatalf("Failed second encryption: %v", err)
	}

	// Ciphertexts should be different (due to random nonce)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Two encryptions of same plaintext should produce different ciphertexts")
	}

	// But both should decrypt to same plaintext
	decrypted1, err := crypto.DecryptAES(ciphertext1, key)
	if err != nil {
		t.Fatalf("Failed to decrypt first ciphertext: %v", err)
	}

	decrypted2, err := crypto.DecryptAES(ciphertext2, key)
	if err != nil {
		t.Fatalf("Failed to decrypt second ciphertext: %v", err)
	}

	if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
		t.Error("Both decryptions should produce original plaintext")
	}
}

// TestAESInvalidCiphertext kiểm tra xử lý ciphertext không hợp lệ
func TestAESInvalidCiphertext(t *testing.T) {
	key, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	tests := []struct {
		name       string
		ciphertext []byte
	}{
		{"Empty", []byte{}},
		{"Too short", []byte{1, 2, 3}},
		{"Random garbage", func() []byte {
			b := make([]byte, 32)
			io.ReadFull(rand.Reader, b)
			return b
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.DecryptAES(tt.ciphertext, key)
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestECDHKeyPairSerialization kiểm tra serialize/deserialize private key
func TestECDHKeyPairSerialization(t *testing.T) {
	// Generate keypair
	priv, pub, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Encode private key
	privBytes := crypto.EncodeECDHPrivateKey(priv)

	// Parse back
	parsedPriv, err := crypto.ParseECDHPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// Verify public key matches
	parsedPub := parsedPriv.PublicKey().Bytes()
	if !bytes.Equal(pub, parsedPub) {
		t.Error("Parsed private key does not produce same public key")
	}
}
