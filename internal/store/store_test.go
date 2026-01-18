package store

import (
	"os"
	"testing"
	"time"
)

func TestCreateAndGet(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := New(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	content := []byte("hello world")
	deleteHash := "somehash"
	expiresAt := time.Now().Add(time.Hour)

	id, err := s.Create(content, deleteHash, expiresAt)
	if err != nil {
		t.Fatal(err)
	}

	paste, err := s.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if paste == nil {
		t.Fatal("expected paste, got nil")
	}
	if string(paste.Content) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", paste.Content, content)
	}
	if paste.DeleteHash != deleteHash {
		t.Errorf("delete hash mismatch: got %q, want %q", paste.DeleteHash, deleteHash)
	}
}

func TestGetMissingID(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := New(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	paste, err := s.Get("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if paste != nil {
		t.Error("expected nil for missing ID")
	}
}

func TestGetExpiredPaste(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := New(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// create paste that expired in the past
	expiresAt := time.Now().Add(-time.Hour)
	id, err := s.Create([]byte("expired"), "", expiresAt)
	if err != nil {
		t.Fatal(err)
	}

	paste, err := s.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if paste != nil {
		t.Error("expected nil for expired paste")
	}
}

func TestDelete(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := New(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, err := s.Create([]byte("to delete"), "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	err = s.Delete(id)
	if err != nil {
		t.Fatal(err)
	}

	paste, err := s.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if paste != nil {
		t.Error("paste should be deleted")
	}
}

func TestCleanup(t *testing.T) {
	tmpFile := t.TempDir() + "/test.db"
	s, err := New(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// create expired paste
	_, err = s.Create([]byte("expired1"), "", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Create([]byte("expired2"), "", time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// create valid paste
	validID, err := s.Create([]byte("valid"), "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	count, err := s.Cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected 2 cleaned up, got %d", count)
	}

	// valid paste should still exist (need to bypass expiry check for this)
	paste, err := s.Get(validID)
	if err != nil {
		t.Fatal(err)
	}
	if paste == nil {
		t.Error("valid paste should not be cleaned up")
	}
}

func TestGenerateID(t *testing.T) {
	id, err := GenerateID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 22 {
		t.Errorf("expected ID length 22, got %d (%q)", len(id), id)
	}

	// verify it's valid base64url (no + or /)
	for _, c := range id {
		if c == '+' || c == '/' || c == '=' {
			t.Errorf("ID contains invalid base64url char: %c", c)
		}
	}
}

func TestIDUniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := GenerateID()
		if err != nil {
			t.Fatal(err)
		}
		if ids[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
