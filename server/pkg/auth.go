package serverpkg

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterResponse struct {
	UserID string `json:"user_id"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	KdfSalt      string `json:"kdf_salt,omitempty"`
}

type LogoutResponse struct {
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

var (
	db                 *sql.DB
	JWTSecretKey       []byte
	argonPepper        string
	accessTokenExpiry  = 15 * time.Minute
	refreshTokenExpiry = 7 * 24 * time.Hour

	// Argon2 parameters
	argonTime    = uint32(1)
	argonMemory  = uint32(64 * 1024) // 64 MB
	argonThreads = uint8(4)
	argonKeyLen  = uint32(32)
)

func InitAuth(database *sql.DB, secretKey, pepper string) error {
	if database == nil {
		return fmt.Errorf("database connection is required")
	}
	if len(secretKey) < 32 {
		return fmt.Errorf("JWT secret key must be at least 32 characters")
	}
	db = database
	JWTSecretKey = []byte(secretKey)
	argonPepper = pepper
	return nil
}
func validatePassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "Password must be at least 8 characters"
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[@#$%^&+=!]`).MatchString(password)

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return false, "Password must contain uppercase, lowercase, numbers and special characters (@#$%^&+=!)"
	}

	return true, ""
}
func validateUsername(username string) (bool, string) {
	if len(username) < 3 || len(username) > 50 {
		return false, "Username must be between 3 and 50 characters"
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(username) {
		return false, "Username can only contain letters, numbers and underscores"
	}

	return true, ""
}

// GenerateJWT creates access token and refresh token for authenticated user
func GenerateJWT(userID string, username string) (accessToken string, refreshToken string, err error) {
	// Create access token (JWT) with 15 minutes expiry
	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"exp":      time.Now().Add(15 * time.Minute).Unix(),
		"iat":      time.Now().Unix(),
		"jti":      uuid.New().String(), // JWT ID (unique identifier)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err = token.SignedString(JWTSecretKey)
	if err != nil {
		return "", "", err
	}

	// Create refresh token (random 32 bytes)
	refreshTokenBytes := make([]byte, 32)
	_, err = rand.Read(refreshTokenBytes)
	if err != nil {
		return "", "", err
	}
	refreshToken = base64.URLEncoding.EncodeToString(refreshTokenBytes)
	// TODO: Store refresh token in database with 7 days expiry
	tokenHash := sha256.Sum256([]byte(refreshToken))
	_, err = db.Exec(
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		userID, hex.EncodeToString(tokenHash[:]),
		time.Now().Add(refreshTokenExpiry),
	)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

// ParseJWT validates and parses a JWT token
func ParseJWT(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return JWTSecretKey, nil
	})

	if err != nil {
		return nil, nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return token, claims, nil
	}

	return nil, nil, jwt.ErrTokenInvalidClaims
}

// RefreshToken generates new access token from valid refresh token
func RefreshToken(oldRefreshToken string) (newAccessToken string, err error) {
	// TODO: Query DB: SELECT user_id, username, expires_at FROM refresh_tokens WHERE token_hash = SHA256(?)
	// TODO: Check if refresh token is expired
	// TODO: Generate new access token
	tokenHash := sha256.Sum256([]byte(oldRefreshToken))
	tokenHashStr := hex.EncodeToString(tokenHash[:])

	var userID string
	var username string
	var expiresAt time.Time

	err = db.QueryRow(
		`SELECT u.id, u.username, rt.expires_at
		 FROM refresh_tokens rt
		 JOIN users u ON rt.user_id = u.id
		 WHERE rt.token_hash = $1`, tokenHashStr).Scan(&userID, &username, &expiresAt)
	if err != nil {
		return "", err
	}
	if time.Now().After(expiresAt) {
		_, _ = db.Exec("DELETE FROM refresh_tokens WHERE token_hash = $1", tokenHashStr)
		return "", jwt.ErrTokenExpired

	}
	jti := uuid.New().String()
	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"exp":      time.Now().Add(accessTokenExpiry).Unix(),
		"iat":      time.Now().Unix(),
		"jti":      jti,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newAccessToken, err = token.SignedString(JWTSecretKey)
	if err != nil {
		return "", err
	}
	return newAccessToken, nil
}

// BlacklistToken adds access token to blacklist on logout
func BlacklistToken(jti string, expiresAt time.Time) error {
	query := `INSERT INTO token_blacklist (jti, expires_at) VALUES ($1, $2) 
	          ON CONFLICT (jti) DO UPDATE SET expires_at = EXCLUDED.expires_at`
	_, err := db.Exec(query, jti, expiresAt)
	return err
}

// ValidateToken checks if token is valid and not blacklisted
func ValidateToken(jti string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM token_blacklist WHERE jti = $1 AND expires_at > NOW())`
	var exists bool
	err := db.QueryRow(query, jti).Scan(&exists)
	return exists, err
}

// RevokeRefreshToken removes refresh token from database
func RevokeRefreshToken(token string) error {
	// TODO: DELETE FROM refresh_tokens WHERE token_hash = SHA256(?)
	tokenHash := sha256.Sum256([]byte(token))
	_, err := db.Exec(
		"DELETE FROM refresh_tokens WHERE token_hash = $1",
		hex.EncodeToString(tokenHash[:]))
	return err
}

// ============================================================
// PASSWORD HASHING (Argon2id)
// ============================================================

// HashPassword uses Argon2id to hash password with salt
func HashPassword(password string, salt []byte) (string, error) {
	pepperPassword := password + argonPepper
	hash := argon2.IDKey([]byte(pepperPassword), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	combined := make([]byte, len(salt)+len(hash))
	copy(combined, salt)
	copy(combined[len(salt):], hash)
	return base64.StdEncoding.EncodeToString(combined), nil
}

// VerifyPassword compares provided password with stored hash
func VerifyPassword(password string, storedHash string, salt []byte) (bool, error) {
	hashedInput, err := HashPassword(password, salt)
	if err != nil {
		return false, err
	}
	return hashedInput == storedHash, nil
}

// GenerateSalt creates a random 16-byte salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// EncodeSalt converts salt bytes to base64
func EncodeSalt(salt []byte) string {
	return base64.StdEncoding.EncodeToString(salt)
}

// DecodeSalt converts base64 salt string back to bytes
func DecodeSalt(saltStr string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(saltStr)
}

// ============================================================
// AUTH HANDLERS
// ============================================================

// Register handles user registration
// POST /api/auth/register
func Register(c *gin.Context) {
	// TODO: Parse request body: username, password
	// TODO: Validate input (length, complexity)
	// TODO: Check if username exists
	// TODO: Generate salt
	// TODO: Hash password with Argon2id
	// TODO: INSERT INTO users (id, username, password_hash, kdf_salt)
	// TODO: Return 201 Created
	var req RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
		return
	}

	if valid, msg := validateUsername(req.Username); !valid {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: msg})
		return
	}

	if valid, msg := validatePassword(req.Password); !valid {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: msg})
		return
	}

	var exists bool
	err := db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
		req.Username).Scan(&exists)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Database error",
		})
		return
	}

	if exists {
		c.JSON(http.StatusConflict, ErrorResponse{
			Error: "Username already exists",
		})
		return
	}

	kdfSalt, err := GenerateSalt()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to generate salt",
		})
		return
	}

	passwordHash, err := HashPassword(req.Password, kdfSalt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to hash password",
		})
		return
	}

	userID := uuid.New()

	// Lưu vào database
	_, err = db.Exec(
		`INSERT INTO users (id, username, password_hash, kdf_salt) 
		 VALUES ($1, $2, $3, $4)`,
		userID, req.Username, passwordHash, EncodeSalt(kdfSalt))

	if err != nil {
		if strings.Contains(err.Error(), "unique constraint") ||
			strings.Contains(err.Error(), "duplicate key") {
			c.JSON(http.StatusConflict, ErrorResponse{
				Error: "Username already exists",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to create user",
		})
		return
	}

	// 201 Created
	c.JSON(http.StatusCreated, RegisterResponse{
		UserID: userID.String(),
	})
}

// Login handles user authentication
// POST /api/auth/login
func Login(c *gin.Context) {
	// TODO: Parse request body: username, password_hash (already hashed on client)
	// TODO: Query DB: SELECT id, password_hash, kdf_salt FROM users WHERE username = ?
	// TODO: Verify password hash
	// TODO: Generate JWT tokens
	// TODO: Return access_token, refresh_token
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request",
		})
		return
	}

	var userID uuid.UUID
	var username string
	var passwordHash string
	var kdfSaltStr string

	err := db.QueryRow(
		`SELECT id, username, password_hash, kdf_salt 
		 FROM users WHERE username = $1`, req.Username).Scan(
		&userID, &username, &passwordHash, &kdfSaltStr)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, ErrorResponse{
				Error: "Invalid credentials",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Database error",
		})
		return
	}
	kdfSaltBytes, err := DecodeSalt(kdfSaltStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Authentication error",
		})
		return
	}

	valid, err := VerifyPassword(req.Password, passwordHash, kdfSaltBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Authentication error",
		})
		return
	}

	if !valid {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error: "Invalid credentials",
		})
		return
	}

	// Tạo JWT token
	accessToken, refreshToken, err := GenerateJWT(userID.String(), username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to generate token",
		})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		KdfSalt:      kdfSaltStr,
	})
}

// Logout handles user logout
// POST /api/auth/logout
func Logout(c *gin.Context) {
	// TODO: Get JWT from Authorization header
	// TODO: Parse JWT to get jti
	// TODO: Blacklist token
	// TODO: Revoke refresh token
	// TODO: Return 200 OK
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Authorization header required",
		})
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid authorization format",
		})
		return
	}

	tokenString := parts[1]

	// Parse token để lấy JTI
	token, claims, err := ParseJWT(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid token"})
		return
	}

	var jti string
	var expiryTime time.Time

	if token != nil && claims != nil {
		// Lấy jti từ claims
		if jtiVal, ok := claims["jti"].(string); ok {
			jti = jtiVal
		}

		// Lấy expiry time từ claims
		if exp, ok := claims["exp"].(float64); ok {
			expiryTime = time.Unix(int64(exp), 0)
		}
	}

	// TODO: Blacklist token
	if jti != "" {
		if expiryTime.IsZero() {
			expiryTime = time.Now().Add(accessTokenExpiry)
		}

		_ = BlacklistToken(jti, expiryTime)
	}

	// TODO: Revoke refresh token
	var refreshTokenReq struct {
		RefreshToken string `json:"refresh_token"`
	}

	if c.Request.Body != nil {
		if err := c.ShouldBindJSON(&refreshTokenReq); err == nil && refreshTokenReq.RefreshToken != "" {
			_ = RevokeRefreshToken(refreshTokenReq.RefreshToken)
		}
	}

	// TODO: Return 200 OK
	c.JSON(http.StatusOK, LogoutResponse{
		Message: "Logged out successfully",
	})
}

// GetSalt returns the KDF salt for a user (used during login)
// GET /api/auth/salt?username=alice
func GetSalt(c *gin.Context) {
	// TODO: Get username from query params
	// TODO: Query DB: SELECT kdf_salt FROM users WHERE username = ?
	// TODO: Return salt in JSON
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Username parameter is required",
		})
		return
	}

	// TODO: Query DB: SELECT kdf_salt FROM users WHERE username = ?
	var kdfSalt string
	err := db.QueryRow(
		"SELECT kdf_salt FROM users WHERE username = $1",
		username).Scan(&kdfSalt)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Error: "User not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Database error",
		})
		return
	}

	// TODO: Return salt in JSON
	c.JSON(http.StatusOK, gin.H{
		"username": username,
		"kdf_salt": kdfSalt,
	})
}
