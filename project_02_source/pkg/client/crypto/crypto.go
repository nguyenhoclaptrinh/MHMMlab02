package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// GenerateAESKey tạo khóa ngẫu nhiên 32-byte cho AES-256
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptAES mã hóa dữ liệu sử dụng AES-GCM
func EncryptAES(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAES giải mã dữ liệu sử dụng AES-GCM
func DecryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("bản mã quá ngắn")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateECDHKeyPair tạo cặp khóa X25519
func GenerateECDHKeyPair() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// DeriveSharedKey tạo khóa bí mật chung từ Private Key của mình và Public Key của người khác
// Kết quả được hash SHA256 để đảm bảo độ dài 32 bytes cho AES
func DeriveSharedKey(priv *ecdh.PrivateKey, pubBytes []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	// Hash shared secret để dùng làm khóa AES
	hash := sha256.Sum256(secret)
	return hash[:], nil
}

// ParseECDHPrivateKey đọc Private Key từ byte (raw bytes)
func ParseECDHPrivateKey(bytes []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(bytes)
}

// EncodeECDHPrivateKey trả về raw bytes của Private Key
func EncodeECDHPrivateKey(priv *ecdh.PrivateKey) []byte {
	return priv.Bytes()
}
