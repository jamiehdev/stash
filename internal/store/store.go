package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"time"

	_ "modernc.org/sqlite"
)

type Paste struct {
	ID         string
	Content    []byte
	DeleteHash string
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

type Store struct {
	db *sql.DB
}

// New creates a new Store with the given database path
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// create table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS pastes (
			id TEXT PRIMARY KEY,
			content BLOB,
			delete_hash TEXT,
			expires_at DATETIME,
			created_at DATETIME
		)
	`)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// GenerateID generates a 128-bit random ID encoded as base64url (~22 chars)
func GenerateID() (string, error) {
	b := make([]byte, 16) // 128 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create stores a new paste and returns its ID
func (s *Store) Create(content []byte, deleteHash string, expiresAt time.Time) (string, error) {
	id, err := GenerateID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	_, err = s.db.Exec(
		`INSERT INTO pastes (id, content, delete_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, content, deleteHash, expiresAt, now,
	)
	if err != nil {
		return "", err
	}

	return id, nil
}

// Get retrieves a paste by ID, returns nil if not found or expired
func (s *Store) Get(id string) (*Paste, error) {
	row := s.db.QueryRow(
		`SELECT id, content, delete_hash, expires_at, created_at FROM pastes WHERE id = ?`,
		id,
	)

	var p Paste
	err := row.Scan(&p.ID, &p.Content, &p.DeleteHash, &p.ExpiresAt, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// check if expired
	if time.Now().After(p.ExpiresAt) {
		return nil, nil
	}

	return &p, nil
}

// Delete removes a paste by ID
func (s *Store) Delete(id string) error {
	_, err := s.db.Exec(`DELETE FROM pastes WHERE id = ?`, id)
	return err
}

// Cleanup removes all expired pastes
func (s *Store) Cleanup() (int64, error) {
	result, err := s.db.Exec(`DELETE FROM pastes WHERE expires_at < ?`, time.Now())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
