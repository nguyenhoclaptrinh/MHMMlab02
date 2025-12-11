package storage

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite" // Import driver sqlite
)

func InitDB(dbFile string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		return nil, err
	}

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

	log.Println("Database đã được khởi tạo thành công.")
	return db, nil
}
