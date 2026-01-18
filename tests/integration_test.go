package tests

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stash/internal/crypto"
	"stash/internal/server"
	"stash/internal/store"
)

func testServer(t *testing.T) (*httptest.Server, *store.Store) {
	s, err := store.New(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	staticFS, _ := fs.Sub(server.StaticFS, "static")
	srv := server.New(s, http.FS(staticFS))
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close() })

	return ts, s
}

type createReq struct {
	Content         string `json:"content"`
	TTL             int    `json:"ttl"`
	DeleteTokenHash string `json:"delete_token_hash"`
}

type createResp struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expires_at"`
}

type pasteResp struct {
	Content   string `json:"content"`
	ExpiresAt string `json:"expires_at"`
}

// simulates CLI creating paste and web reading it
func TestCLICreateWebRead(t *testing.T) {
	ts, _ := testServer(t)

	// CLI creates paste
	plaintext := []byte("secret from CLI")
	key, _ := crypto.GenerateKey()
	blob, _ := crypto.Encrypt(plaintext, key)

	deleteToken := "test-delete-token"
	hash := sha256.Sum256([]byte(deleteToken))
	deleteHash := hex.EncodeToString(hash[:])

	reqBody, _ := json.Marshal(createReq{
		Content:         crypto.EncodeBlob(blob),
		TTL:             60,
		DeleteTokenHash: deleteHash,
	})

	resp, err := http.Post(ts.URL+"/api/paste", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr createResp
	json.NewDecoder(resp.Body).Decode(&cr)

	// web (simulated) fetches and decrypts
	getResp, err := http.Get(ts.URL + "/api/paste/" + cr.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()

	var gr pasteResp
	json.NewDecoder(getResp.Body).Decode(&gr)

	decBlob, _ := crypto.DecodeBlob(gr.Content)
	decrypted, err := crypto.Decrypt(decBlob, key)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// simulates web creating paste and CLI reading it
func TestWebCreateCLIRead(t *testing.T) {
	ts, _ := testServer(t)

	// web creates paste (same API as CLI)
	plaintext := []byte("secret from web")
	key, _ := crypto.GenerateKey()
	blob, _ := crypto.Encrypt(plaintext, key)

	reqBody, _ := json.Marshal(createReq{
		Content: crypto.EncodeBlob(blob),
		TTL:     60,
	})

	resp, err := http.Post(ts.URL+"/api/paste", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr createResp
	json.NewDecoder(resp.Body).Decode(&cr)

	// CLI (simulated) fetches and decrypts
	getResp, err := http.Get(ts.URL + "/api/paste/" + cr.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()

	var gr pasteResp
	json.NewDecoder(getResp.Body).Decode(&gr)

	decBlob, _ := crypto.DecodeBlob(gr.Content)
	decrypted, err := crypto.Decrypt(decBlob, key)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestExpiry(t *testing.T) {
	ts, s := testServer(t)

	// create paste with very short TTL
	key, _ := crypto.GenerateKey()
	blob, _ := crypto.Encrypt([]byte("will expire"), key)

	// create directly in store with past expiry
	expiresAt := time.Now().Add(-1 * time.Second)
	id, err := s.Create(blob, "", expiresAt)
	if err != nil {
		t.Fatal(err)
	}

	// should return 404
	resp, err := http.Get(ts.URL + "/api/paste/" + id)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for expired paste, got %d", resp.StatusCode)
	}
}

func TestDeleteFlow(t *testing.T) {
	ts, _ := testServer(t)

	// create paste with delete token
	key, _ := crypto.GenerateKey()
	blob, _ := crypto.Encrypt([]byte("to delete"), key)

	deleteToken := "my-delete-token"
	hash := sha256.Sum256([]byte(deleteToken))
	deleteHash := hex.EncodeToString(hash[:])

	reqBody, _ := json.Marshal(createReq{
		Content:         crypto.EncodeBlob(blob),
		TTL:             3600,
		DeleteTokenHash: deleteHash,
	})

	resp, err := http.Post(ts.URL+"/api/paste", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr createResp
	json.NewDecoder(resp.Body).Decode(&cr)

	// verify paste exists
	getResp, _ := http.Get(ts.URL + "/api/paste/" + cr.ID)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatal("paste should exist")
	}

	// delete paste
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/paste/"+cr.ID+"?token="+deleteToken, nil)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	delResp.Body.Close()

	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", delResp.StatusCode)
	}

	// verify paste is gone
	getResp2, _ := http.Get(ts.URL + "/api/paste/" + cr.ID)
	getResp2.Body.Close()
	if getResp2.StatusCode != http.StatusNotFound {
		t.Error("paste should be deleted")
	}
}

func TestCryptoCompatibility(t *testing.T) {
	// test that Go crypto matches expected format for web crypto interop
	key, _ := crypto.GenerateKey()
	if len(key) != 32 {
		t.Errorf("key should be 32 bytes for AES-256")
	}

	plaintext := []byte("test data for interop")
	blob, _ := crypto.Encrypt(plaintext, key)

	// verify blob format: version(1) + nonce(12) + ciphertext
	if blob[0] != 0x01 {
		t.Errorf("blob should start with version 0x01")
	}

	// verify roundtrip
	decrypted, err := crypto.Decrypt(blob, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("roundtrip failed")
	}
}

func TestCleanupIntegration(t *testing.T) {
	_, s := testServer(t)

	// create expired pastes directly
	key, _ := crypto.GenerateKey()
	blob, _ := crypto.Encrypt([]byte("expired1"), key)
	s.Create(blob, "", time.Now().Add(-time.Hour))

	blob2, _ := crypto.Encrypt([]byte("expired2"), key)
	s.Create(blob2, "", time.Now().Add(-time.Hour))

	// create valid paste
	blob3, _ := crypto.Encrypt([]byte("valid"), key)
	validID, _ := s.Create(blob3, "", time.Now().Add(time.Hour))

	// run cleanup
	count, err := s.Cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected 2 cleaned up, got %d", count)
	}

	// valid paste should still exist
	paste, err := s.Get(validID)
	if err != nil {
		t.Fatal(err)
	}
	if paste == nil {
		t.Error("valid paste should still exist")
	}
}
