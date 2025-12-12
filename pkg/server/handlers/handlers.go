package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"lab02/pkg/models"
	"lab02/pkg/server/crypto"
)

type Server struct {
	DB *sql.DB
}

func NewServer(db *sql.DB) *Server {
	return &Server{DB: db}
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/register", s.HandleRegister)
	mux.HandleFunc("/login", s.HandleLogin)
	mux.HandleFunc("/notes", s.HandleNotes)
	mux.HandleFunc("/notes/", s.HandleNoteDetail)
	mux.HandleFunc("/users/", s.HandleGetUser)
	mux.HandleFunc("/notes/share", s.HandleShareNote)
	mux.HandleFunc("/notes/share-link", s.HandleGenerateShareLink)
	mux.HandleFunc("/public/notes/", s.HandleGetPublicNote)
	mux.HandleFunc("/notes/shared-out", s.HandleListSharedOut)
}

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
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
	err := s.DB.QueryRow("SELECT username FROM users WHERE username = ?", req.Username).Scan(&exists)
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

	_, err = s.DB.Exec("INSERT INTO users (username, password_hash, salt, public_key) VALUES (?, ?, ?, ?)",
		req.Username, hashedPwd, salt, req.PublicKey)
	if err != nil {
		http.Error(w, "Lỗi server nội bộ", http.StatusInternalServerError)
		log.Println("Register Error:", err)
		return
	}

	log.Printf("Người dùng %s đăng ký thành công", req.Username)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
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
	err := s.DB.QueryRow("SELECT username, password_hash, salt, public_key FROM users WHERE username = ?", req.Username).
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

func (s *Server) HandleNotes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.createNote(w, r)
	case http.MethodGet:
		s.listNotes(w, r)
	case http.MethodDelete:
		s.HandleDeleteNote(w, r)
	default:
		http.Error(w, "Phương thức không được phép", http.StatusMethodNotAllowed)
	}
}

func (s *Server) createNote(w http.ResponseWriter, r *http.Request) {
	var note models.Note
	if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
		http.Error(w, "Yêu cầu không hợp lệ", http.StatusBadRequest)
		return
	}

	// Generate random note ID instead of time-based to avoid collisions
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	note.ID = hex.EncodeToString(idBytes)
	note.CreatedAt = time.Now()

	// Kiểm tra permission
	user := s.getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}
	note.OwnerID = user.ID // Enforce owner is the authenticated user

	// Lưu SharedKey cho chủ sở hữu
	ownerKey, ok := note.SharedKeys[note.OwnerID]
	if !ok {
		http.Error(w, "Thiếu khóa của chủ sở hữu", http.StatusBadRequest)
		return
	}

	tx, err := s.DB.Begin()
	if err != nil {
		http.Error(w, "Lỗi server", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec(`INSERT INTO notes (id, owner_id, title, filename, content, encrypted, created_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		note.ID, note.OwnerID, note.Title, note.Filename, note.Content, note.Encrypted, note.CreatedAt)
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

func (s *Server) listNotes(w http.ResponseWriter, r *http.Request) {
	user := s.getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}

	// Lấy ghi chú sở hữu HOẶC được chia sẻ
	rows, err := s.DB.Query(`
		SELECT DISTINCT n.id, n.owner_id, n.title, n.filename, n.encrypted 
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
		err := rows.Scan(&n.ID, &n.OwnerID, &n.Title, &n.Filename, &n.Encrypted)
		if err != nil {
			log.Println("Scan error:", err)
			continue
		}
		result = append(result, n)
	}

	json.NewEncoder(w).Encode(result)
}

func (s *Server) HandleNoteDetail(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/notes/"):]
	user := s.getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}

	var n models.Note
	err := s.DB.QueryRow(`SELECT id, owner_id, title, filename, content, encrypted, created_at
		FROM notes WHERE id = ?`, id).
		Scan(&n.ID, &n.OwnerID, &n.Title, &n.Filename, &n.Content, &n.Encrypted, &n.CreatedAt)

	if err == sql.ErrNoRows {
		http.Error(w, "Không tìm thấy ghi chú", http.StatusNotFound)
		return
	}

	var encryptedKey []byte
	err = s.DB.QueryRow("SELECT encrypted_key FROM shared_keys WHERE note_id = ? AND user_id = ?", id, user.ID).Scan(&encryptedKey)
	if err == sql.ErrNoRows {
		http.Error(w, "Bị cấm", http.StatusForbidden)
		return
	}

	n.SharedKeys = make(map[string][]byte)
	n.SharedKeys[user.ID] = encryptedKey

	json.NewEncoder(w).Encode(n)
}

func (s *Server) HandleShareNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Phương thức không được phép", http.StatusMethodNotAllowed)
		return
	}

	user := s.getUserFromToken(r)
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

	var ownerID string
	err := s.DB.QueryRow("SELECT owner_id FROM notes WHERE id = ?", req.NoteID).Scan(&ownerID)
	if err == sql.ErrNoRows {
		http.Error(w, "Không tìm thấy ghi chú", http.StatusNotFound)
		return
	}
	if ownerID != user.ID {
		http.Error(w, "Chỉ chủ sở hữu mới được chia sẻ", http.StatusForbidden)
		return
	}

	_, err = s.DB.Exec("INSERT INTO shared_keys (note_id, user_id, encrypted_key) VALUES (?, ?, ?)",
		req.NoteID, req.TargetUser, req.EncryptedKey)
	if err != nil {
		http.Error(w, "Lỗi chia sẻ (có thể đã chia sẻ rồi)", http.StatusInternalServerError)
		return
	}

	log.Printf("Ghi chú %s đã được chia sẻ với %s bởi %s", req.NoteID, req.TargetUser, user.Username)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) HandleGenerateShareLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Phương thức không được phép", http.StatusMethodNotAllowed)
		return
	}

	user := s.getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}

	var req struct {
		NoteID    string `json:"note_id"`
		MaxVisits int    `json:"max_visits"`
		Duration  string `json:"duration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Yêu cầu không hợp lệ", http.StatusBadRequest)
		return
	}

	// Verify ownership
	var ownerID string
	err := s.DB.QueryRow("SELECT owner_id FROM notes WHERE id = ?", req.NoteID).Scan(&ownerID)
	if err != nil {
		http.Error(w, "Ghi chú không tồn tại", http.StatusNotFound)
		return
	}
	if ownerID != user.ID {
		http.Error(w, "Chỉ chủ sở hữu mới được tạo link", http.StatusForbidden)
		return
	}

	// Create ShareLink
	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	var expiresAt time.Time
	if req.Duration != "" {
		dur, err := time.ParseDuration(req.Duration)
		if err == nil {
			expiresAt = time.Now().Add(dur)
		}
	}

	_, err = s.DB.Exec(`INSERT INTO share_links (token, note_id, created_at, expires_at, max_visits, visit_count)
		VALUES (?, ?, ?, ?, ?, 0)`,
		token, req.NoteID, time.Now(), expiresAt, req.MaxVisits)
	if err != nil {
		http.Error(w, "Lỗi tạo link chia sẻ", http.StatusInternalServerError)
		log.Println("Create Link Error:", err)
		return
	}

	json.NewEncoder(w).Encode(struct {
		ShareToken string `json:"share_token"`
	}{ShareToken: token})
}

func (s *Server) HandleGetPublicNote(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Path[len("/public/notes/"):]

	var sl models.ShareLink
	err := s.DB.QueryRow(`
		SELECT token, note_id, created_at, expires_at, max_visits, visit_count 
		FROM share_links WHERE token = ?`, token).
		Scan(&sl.Token, &sl.NoteID, &sl.CreatedAt, &sl.ExpiresAt, &sl.MaxVisits, &sl.VisitCount)

	if err == sql.ErrNoRows {
		http.Error(w, "Link không tồn tại hoặc đã bị hủy", http.StatusNotFound) // 404 for security/cleanliness
		return
	}

	// Check Limits
	expired := false
	if !sl.ExpiresAt.IsZero() && time.Now().After(sl.ExpiresAt) {
		expired = true
	}
	if sl.MaxVisits > 0 && sl.VisitCount >= sl.MaxVisits {
		expired = true
	}

	if expired {
		// Lazy Delete
		s.DB.Exec("DELETE FROM share_links WHERE token = ?", token)
		http.Error(w, "Link đã hết hạn hoặc hết lượt truy cập", http.StatusGone) // 410
		return
	}

	// Get Note Content
	var n models.Note
	err = s.DB.QueryRow(`SELECT id, owner_id, title, filename, content, encrypted, created_at 
		FROM notes WHERE id = ?`, sl.NoteID).
		Scan(&n.ID, &n.OwnerID, &n.Title, &n.Filename, &n.Content, &n.Encrypted, &n.CreatedAt)

	if err != nil {
		http.Error(w, "Không tìm thấy ghi chú gốc", http.StatusNotFound)
		return
	}

	// Update Visit Count
	_, err = s.DB.Exec("UPDATE share_links SET visit_count = visit_count + 1 WHERE token = ?", token)
	if err != nil {
		log.Println("Update visit count failed:", err)
		// Non-critical error, continue to serve note
	}

	json.NewEncoder(w).Encode(n)
}

func (s *Server) getUserFromToken(r *http.Request) *models.User {
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
	err = s.DB.QueryRow("SELECT username, public_key FROM users WHERE username = ?", username).
		Scan(&u.Username, &u.PublicKey)
	if err != nil {
		return nil
	}
	u.ID = u.Username
	return &u
}

func (s *Server) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Path[len("/users/"):]

	var u models.User
	err := s.DB.QueryRow("SELECT username, public_key FROM users WHERE username = ?", username).
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

func (s *Server) HandleDeleteNote(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Thiếu ID ghi chú", http.StatusBadRequest)
		return
	}

	user := s.getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}

	// Kiểm tra quyền (chỉ chủ sở hữu)
	var ownerID string
	err := s.DB.QueryRow("SELECT owner_id FROM notes WHERE id = ?", id).Scan(&ownerID)
	if err == sql.ErrNoRows {
		http.Error(w, "Không tìm thấy ghi chú", http.StatusNotFound)
		return
	}
	if ownerID != user.ID {
		http.Error(w, "Chỉ chủ sở hữu mới được xóa", http.StatusForbidden)
		return
	}

	// Xóa
	tx, err := s.DB.Begin()
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

func (s *Server) HandleListSharedOut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Phương thức không được phép", http.StatusMethodNotAllowed)
		return
	}

	user := s.getUserFromToken(r)
	if user == nil {
		http.Error(w, "Không được phép", http.StatusUnauthorized)
		return
	}

	// Query: Find notes owned by current user that are shared with OTHERS (sk.user_id != user.ID)
	// We join shared_keys with notes to get title/filename
	rows, err := s.DB.Query(`
		SELECT n.id, n.title, n.filename, sk.user_id 
		FROM notes n
		JOIN shared_keys sk ON n.id = sk.note_id
		WHERE n.owner_id = ? AND sk.user_id != ?
	`, user.ID, user.ID)

	if err != nil {
		http.Error(w, "Lỗi truy vấn db", http.StatusInternalServerError)
		log.Println("List Shared Out Error:", err)
		return
	}
	defer rows.Close()

	var result []models.SharedNoteInfo
	for rows.Next() {
		var info models.SharedNoteInfo
		err := rows.Scan(&info.NoteID, &info.Title, &info.Filename, &info.SharedWith)
		if err != nil {
			log.Println("Scan error:", err)
			continue
		}
		result = append(result, info)
	}

	if result == nil {
		result = []models.SharedNoteInfo{}
	}
	json.NewEncoder(w).Encode(result)
}
