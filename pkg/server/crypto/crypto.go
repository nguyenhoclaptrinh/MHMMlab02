package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("my_super_secret_key_for_lab02") // Trong thực tế nên để trong biến môi trường

// GenerateSalt tạo chuỗi salt ngẫu nhiên (16 bytes hex)
func GenerateSalt() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// HashPassword băm mật khẩu kèm salt với SHA256
func HashPassword(password, salt string) string {
	// Kết hợp password + salt
	data := []byte(password + salt)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// GenerateJWT tạo token JWT cho user
func GenerateJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"sub": username,
		"exp": time.Now().Add(24 * time.Hour).Unix(), // Hết hạn sau 24h
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ValidateJWT xác thực token và trả về username
func ValidateJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if username, ok := claims["sub"].(string); ok {
			return username, nil
		}
	}
	return "", errors.New("invalid token claims")
}
