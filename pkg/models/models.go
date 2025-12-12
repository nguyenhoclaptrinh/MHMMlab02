package models

import (
	"time"
)

// User represents a registered user
type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`          // Never return password hash in JSON
	PublicKey    []byte `json:"public_key"` // PEM encoded public key
	PrivateKey   []byte `json:"-"`          // Encrypted private key (stored on server for convenience in this lab, or kept local-only in real apps)
}

// Note represents an encrypted note
type Note struct {
	ID        string    `json:"id"`
	OwnerID   string    `json:"owner_id"`
	Title     string    `json:"title"`    // Possibly encrypted in a real app, plaintext here for listing
	Filename  string    `json:"filename"` // Original filename
	Content   []byte    `json:"content"`  // AES-GCM encrypted content
	Encrypted bool      `json:"encrypted"`
	CreatedAt time.Time `json:"created_at"`

	// SharedKeys maps UserID to the NoteKey encrypted with that User's Public Key
	SharedKeys map[string][]byte `json:"shared_keys,omitempty"`
}

// ShareLink represents a public access link for a note
type ShareLink struct {
	Token      string    `json:"token"`
	NoteID     string    `json:"note_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"` // Zero if unlimited
	MaxVisits  int       `json:"max_visits"` // 0 if unlimited
	VisitCount int       `json:"visit_count"`
}

// AuthRequest for login/register
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// SharedNoteInfo represents information about a note shared with another user
type SharedNoteInfo struct {
	NoteID     string `json:"note_id"`
	Title      string `json:"title"`
	Filename   string `json:"filename"`
	SharedWith string `json:"shared_with"` // Username of recipient
}

// AuthResponse returns token and user info
type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}
