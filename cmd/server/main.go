package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"lab02/pkg/crypto"
	"lab02/pkg/models"

	_ "modernc.org/sqlite" // Import driver sqlite
)

const (
	Port   = ":8080"
	DBFile = "server.db"
)

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite", DBFile)
	if err != nil {
		log.Fatal("Lỗi mở database:", err)
	}

	// Tạo bảng Users
	// Lưu ý: Nếu database cũ đã tồn tại, cần xóa file server.db hoặc chạy câu lệnh ALTER TABLE thủ công.
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT,
		salt TEXT,
		public_key BLOB
	)`)
	if err != nil {
		log.Fatal("Lỗi tạo bảng users:", err)
	}

	// Tạo bảng Notes
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS notes (
		id TEXT PRIMARY KEY,
		owner_id TEXT,
		title TEXT,
		filename TEXT,
		content BLOB,
		encrypted BOOLEAN,
		created_at DATETIME,
		expires_at DATETIME,
		share_token TEXT
	)`)
	if err != nil {
		log.Fatal("Lỗi tạo bảng notes:", err)
	}

	// Tạo bảng SharedKeys
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS shared_keys (
		note_id TEXT,
		user_id TEXT,
		encrypted_key BLOB,
		PRIMARY KEY (note_id, user_id)
	)`)
	if err != nil {
		log.Fatal("Lỗi tạo bảng shared_keys:", err)
	}

	log.Println("Database đã được khởi tạo thành công.")
}

func main() {
	initDB()
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", handleRegister)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/notes", handleNotes)
	mux.HandleFunc("/notes/", handleNoteDetail)
	mux.HandleFunc("/users/", handleGetUser)
	mux.HandleFunc("/notes/share", handleShareNote)
	mux.HandleFunc("/notes/share-link", handleGenerateShareLink)
	mux.HandleFunc("/public/notes/", handleGetPublicNote)

	log.Printf("Máy chủ đang khởi động tại %s...", Port)
	log.Fatal(http.ListenAndServe(Port, mux))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Phương thức không được phép", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		PublicKey []byte `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Yêu cầu không hợp lệ", http.StatusBadRequest)
		return
	}

	// Kiểm tra user tồn tại
	var exists string
	err := db.QueryRow("SELECT username FROM users WHERE username = ?", req.Username).Scan(&exists)
	if err == nil {
		http.Error(w, "Người dùng đã tồn tại", http.StatusConflict)
		return
	}

	// Tạo Salt và Hash password
	salt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "Lỗi tạo salt", http.StatusInternalServerError)
		return
	}
	hashedPwd := crypto.HashPassword(req.Password, salt)

	_, err = db.Exec("INSERT INTO users (username, password_hash, salt, public_key) VALUES (?, ?, ?, ?)",
		req.Username, hashedPwd, salt, req.PublicKey)
	if err != nil {
		http.Error(w, "Lỗi server nội bộ", http.StatusInternalServerError)
		log.Println("Register Error:", err)
		return
	}

	log.Printf("Người dùng %s đăng ký thành công", req.Username)
	w.WriteHeader(http.StatusCreated)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Phương thức không được phép", http.StatusMethodNotAllowed)
		return
	}

	var req models.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Yêu cầu không hợp lệ", http.StatusBadRequest)
		return
	}

	var user models.User
	var pwdHash string
	var salt string
	err := db.QueryRow("SELECT username, password_hash, salt, public_key FROM users WHERE username = ?", req.Username).
		Scan(&user.Username, &pwdHash, &salt, &user.PublicKey)

	if err != nil || pwdHash != crypto.HashPassword(req.Password, salt) {
		http.Error(w, "Thông tin đăng nhập không hợp lệ", http.StatusUnauthorized)
		return
	}
	user.ID = user.Username

	token, err := crypto.GenerateJWT(user.Username)
	if err != nil {
		http.Error(w, "Lỗi tạo token", http.StatusInternalServerError)
		return
	}

	resp := models.AuthResponse{
		Token: token,
		User:  user,
	}
	json.NewEncoder(w).Encode(resp)
}

func handleNotes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		createNote(w, r)
	case http.MethodGet:
		listNotes(w, r)
	case http.MethodDelete:
		handleDeleteNote(w, r)
	default:
		http.Error(w, "Phương thức không được phép", http.StatusMethodNotAllowed)
	}
}

func createNote(w http.ResponseWriter, r *http.Request) {
	var note models.Note
	if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
		http.Error(w, "Yêu cầu không hợp lệ", http.StatusBadRequest)
		return
	}

	note.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	note.CreatedAt = time.Now()

	// Lưu SharedKey cho chủ sở hữu
	ownerKey, ok := note.SharedKeys[note.OwnerID]
	if !ok {
		http.Error(w, "Thiếu khóa của chủ sở hữu", http.StatusBadRequest)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Lỗi server", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec(`INSERT INTO notes (id, owner_id, title, filename, content, encrypted, created_at, expires_at, share_token) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		note.ID, note.OwnerID, note.Title, note.Filename, note.Content, note.Encrypted, note.CreatedAt, note.ExpiresAt, "") // Init share_token empty
	if err != nil {
		tx.Rollback()
		http.Error(w, "Lỗi lưu ghi chú", http.StatusInternalServerError)
		log.Println("Insert Note Error:", err)
		return
	}

	_, err = tx.Exec("INSERT INTO shared_keys (note_id, user_id, encrypted_key) VALUES (?, ?, ?)",
		note.ID, note.OwnerID, ownerKey)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Lỗi lưu khóa", http.StatusInternalServerError)
		return
	}

	tx.Commit()
	json.NewEncoder(w).Encode(note)
}

func listNotes(w http.ResponseWriter, r *http.Request) {
	user := getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}

	// Lấy ghi chú sở hữu HOẶC được chia sẻ
	rows, err := db.Query(`
		SELECT DISTINCT n.id, n.owner_id, n.title, n.filename, n.encrypted, n.share_token 
		FROM notes n
		LEFT JOIN shared_keys sk ON n.id = sk.note_id
		WHERE n.owner_id = ? OR sk.user_id = ?
	`, user.ID, user.ID)

	if err != nil {
		http.Error(w, "Lỗi truy vấn db", http.StatusInternalServerError)
		log.Println("List Query Error:", err)
		return
	}
	defer rows.Close()

	var result []models.Note
	for rows.Next() {
		var n models.Note
		var token sql.NullString // Handle NULL share_token
		err := rows.Scan(&n.ID, &n.OwnerID, &n.Title, &n.Filename, &n.Encrypted, &token)
		if err != nil {
			log.Println("Scan error:", err)
			continue
		}
		if token.Valid {
			n.ShareToken = token.String
		}
		result = append(result, n)
	}

	json.NewEncoder(w).Encode(result)
}

func handleNoteDetail(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/notes/"):]
	user := getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}

	var n models.Note
	var token sql.NullString
	err := db.QueryRow(`SELECT id, owner_id, title, filename, content, encrypted, created_at, expires_at, share_token 
		FROM notes WHERE id = ?`, id).
		Scan(&n.ID, &n.OwnerID, &n.Title, &n.Filename, &n.Content, &n.Encrypted, &n.CreatedAt, &n.ExpiresAt, &token)

	if err == sql.ErrNoRows {
		http.Error(w, "Không tìm thấy ghi chú", http.StatusNotFound)
		return
	}
	if token.Valid {
		n.ShareToken = token.String
	}

	// Kiểm tra hết hạn
	if !n.ExpiresAt.IsZero() && time.Now().After(n.ExpiresAt) {
		http.Error(w, "Ghi chú đã hết hạn", http.StatusGone)
		return
	}

	// Kiểm tra quyền (phải có entry trong shared_keys)
	var encryptedKey []byte
	err = db.QueryRow("SELECT encrypted_key FROM shared_keys WHERE note_id = ? AND user_id = ?", id, user.ID).Scan(&encryptedKey)
	if err == sql.ErrNoRows {
		http.Error(w, "Bị cấm", http.StatusForbidden)
		return
	}

	n.SharedKeys = make(map[string][]byte)
	n.SharedKeys[user.ID] = encryptedKey // Chỉ trả về key của user đang request để bảo mật

	json.NewEncoder(w).Encode(n)
}

func handleShareNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Phương thức không được phép", http.StatusMethodNotAllowed)
		return
	}

	user := getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}

	var req struct {
		NoteID       string `json:"note_id"`
		TargetUser   string `json:"target_user"`
		EncryptedKey []byte `json:"encrypted_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Yêu cầu không hợp lệ", http.StatusBadRequest)
		return
	}

	// Kiểm tra quyền sở hữu
	var ownerID string
	err := db.QueryRow("SELECT owner_id FROM notes WHERE id = ?", req.NoteID).Scan(&ownerID)
	if err == sql.ErrNoRows {
		http.Error(w, "Không tìm thấy ghi chú", http.StatusNotFound)
		return
	}
	if ownerID != user.ID {
		http.Error(w, "Chỉ chủ sở hữu mới được chia sẻ", http.StatusForbidden)
		return
	}

	// Thêm shared key
	_, err = db.Exec("INSERT INTO shared_keys (note_id, user_id, encrypted_key) VALUES (?, ?, ?)",
		req.NoteID, req.TargetUser, req.EncryptedKey)
	if err != nil {
		http.Error(w, "Lỗi chia sẻ (có thể đã chia sẻ rồi)", http.StatusInternalServerError)
		return
	}

	log.Printf("Ghi chú %s đã được chia sẻ với %s bởi %s", req.NoteID, req.TargetUser, user.Username)
	w.WriteHeader(http.StatusOK)
}

func handleGenerateShareLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Phương thức không được phép", http.StatusMethodNotAllowed)
		return
	}

	user := getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}

	var req struct {
		NoteID string `json:"note_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println("GenerateLink Decode Error:", err)
		http.Error(w, "Yêu cầu không hợp lệ", http.StatusBadRequest)
		return
	}

	var ownerID string
	var currentToken sql.NullString
	err := db.QueryRow("SELECT owner_id, share_token FROM notes WHERE id = ?", req.NoteID).Scan(&ownerID, &currentToken)
	if err != nil {
		log.Printf("GenerateLink Query Error for NoteID %s: %v", req.NoteID, err)
		http.Error(w, "Ghi chú không tồn tại", http.StatusNotFound)
		return
	}

	if ownerID != user.ID {
		log.Printf("GenerateLink Forbidden: User %s is not owner of %s", user.ID, req.NoteID)
		http.Error(w, "Chỉ chủ sở hữu mới được tạo link", http.StatusForbidden)
		return
	}

	finalToken := ""
	if currentToken.Valid && currentToken.String != "" {
		finalToken = currentToken.String
	} else {
		tokenBytes := make([]byte, 16)
		rand.Read(tokenBytes)
		finalToken = hex.EncodeToString(tokenBytes)
		_, err := db.Exec("UPDATE notes SET share_token = ? WHERE id = ?", finalToken, req.NoteID)
		if err != nil {
			log.Println("GenerateLink Update Error:", err)
			http.Error(w, "Lỗi cập nhật token", http.StatusInternalServerError)
			return
		}
	}

	json.NewEncoder(w).Encode(struct {
		ShareToken string `json:"share_token"`
	}{ShareToken: finalToken})
}

func handleGetPublicNote(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Path[len("/public/notes/"):]

	var n models.Note
	err := db.QueryRow(`SELECT id, owner_id, title, filename, content, encrypted, created_at, expires_at, share_token 
		FROM notes WHERE share_token = ?`, token).
		Scan(&n.ID, &n.OwnerID, &n.Title, &n.Filename, &n.Content, &n.Encrypted, &n.CreatedAt, &n.ExpiresAt, &n.ShareToken)

	if err == sql.ErrNoRows {
		http.Error(w, "Link không hợp lệ", http.StatusNotFound)
		return
	}

	if !n.ExpiresAt.IsZero() && time.Now().After(n.ExpiresAt) {
		http.Error(w, "Ghi chú đã hết hạn", http.StatusGone)
		return
	}

	json.NewEncoder(w).Encode(n)
}

func getUserFromToken(r *http.Request) *models.User {
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || auth[:7] != "Bearer " {
		return nil
	}
	tokenString := auth[7:]

	username, err := crypto.ValidateJWT(tokenString)
	if err != nil {
		return nil
	}

	var u models.User
	err = db.QueryRow("SELECT username, public_key FROM users WHERE username = ?", username).
		Scan(&u.Username, &u.PublicKey)
	if err != nil {
		return nil
	}
	u.ID = u.Username
	return &u
}

func handleGetUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Path[len("/users/"):]

	var u models.User
	err := db.QueryRow("SELECT username, public_key FROM users WHERE username = ?", username).
		Scan(&u.Username, &u.PublicKey)

	if err == sql.ErrNoRows {
		http.Error(w, "Không tìm thấy người dùng", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(struct {
		Username  string `json:"username"`
		PublicKey []byte `json:"public_key"`
	}{
		Username:  u.Username,
		PublicKey: u.PublicKey,
	})
}

func handleDeleteNote(w http.ResponseWriter, r *http.Request) {
	// Lấy ID từ Query param hoặc trong Body. Tốt nhất là /notes?id=... hoặc parse URL nếu route là /notes/{id}
	// Nhưng ở handleNotes (route /notes), r.URL.Path là /notes.
	// Client sẽ gửi request DELETE /notes?id=... hoặc chúng ta sửa route main.
	// Hiện tại router: /notes -> handleNotes. /notes/ -> handleNoteDetail.
	// DELETE thường hướng tới resource cụ thể.
	// Cách đơn giản nhất theo kiến trúc hiện tại:
	// Client gửi DELETE /notes/{id}. Request này sẽ rơi vào handleNoteDetail nếu ta config lại, hoặc handleNotes xử lý query param.
	// Nhưng `handleNoteDetail` đang match prefix `/notes/`.
	// Vậy nên ta sẽ thêm logic xử lý DELETE vào `handleNoteDetail` hoặc `handleNotes`.
	// Để chuẩn REST, DELETE /notes/{id} nên được xử lý ở `handleNoteDetail`.

	// Tuy nhiên, tôi đang ở hàm `handleDeleteNote` được gọi từ `handleNotes`.
	// `handleNotes` được map vào `/notes` (không có slash cuối hoặc ID).
	// Vậy Client phải gọi DELETE /notes với Body chứa ID hoặc Query Param.
	// Hãy dùng Query Param: DELETE /notes?id=...

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Thiếu ID ghi chú", http.StatusBadRequest)
		return
	}

	user := getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}

	// Kiểm tra quyền (chỉ chủ sở hữu)
	var ownerID string
	err := db.QueryRow("SELECT owner_id FROM notes WHERE id = ?", id).Scan(&ownerID)
	if err == sql.ErrNoRows {
		http.Error(w, "Không tìm thấy ghi chú", http.StatusNotFound)
		return
	}
	if ownerID != user.ID {
		http.Error(w, "Chỉ chủ sở hữu mới được xóa", http.StatusForbidden)
		return
	}

	// Xóa
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Lỗi server", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("DELETE FROM shared_keys WHERE note_id = ?", id)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Lỗi xóa shared keys", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("DELETE FROM notes WHERE id = ?", id)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Lỗi xóa ghi chú", http.StatusInternalServerError)
		return
	}

	tx.Commit()
	w.WriteHeader(http.StatusOK)
	log.Printf("Ghi chú %s đã được xóa bởi %s", id, user.Username)
}
