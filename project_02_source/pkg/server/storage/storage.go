package storage

import (
	"database/sql"
	"fmt" // Added fmt import
	"log"

	_ "modernc.org/sqlite" // Import driver sqlite
)

func InitDB(dbPath string) (*sql.DB, error) { // Changed dbFile to dbPath
	// Sử dụng DSN parameters để cấu hình connection pool connection nào cũng có param này
	// _pragma=journal_mode(WAL): Write-Ahead Logging cho concurrency
	// _pragma=busy_timeout(5000): Đợi lock 5s thay vì fail ngay
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)", dbPath)

	db, err := sql.Open("sqlite", dsn) // Used DSN
	if err != nil {
		return nil, err
	}

	// Ping để kiểm tra kết nối
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Optimization: Set MaxOpenConns to allow concurrency (optional, default is unlimited)
	db.SetMaxOpenConns(10)

	// Tạo bảng Users
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT,
		salt TEXT,
		public_key BLOB
	)`)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	// Index cho notes
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_notes_owner ON notes(owner_id);`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_notes_share_token ON notes(share_token);`); err != nil {
		return nil, err
	}

	// Tạo bảng SharedKeys
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS shared_keys (
		note_id TEXT,
		user_id TEXT,
		encrypted_key BLOB,
		PRIMARY KEY (note_id, user_id)
	)`)
	if err != nil {
		return nil, err
	}

	// Index cho shared_keys
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_shared_keys_user ON shared_keys(user_id);`); err != nil {
		return nil, err
	}

	log.Println("Database đã được khởi tạo thành công.")
	return db, nil
}
