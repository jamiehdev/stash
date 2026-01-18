package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"stash/internal/store"
)

func testStore(t *testing.T) *store.Store {
	s, err := store.New(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreatePaste(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	body := `{"content":"dGVzdA","ttl":60}`
	req := httptest.NewRequest("POST", "/api/paste", strings.NewReader(body))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp CreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestGetPaste(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	// create paste directly
	content := []byte("hello")
	id, _ := s.Create(content, "", time.Now().Add(time.Hour))

	req := httptest.NewRequest("GET", "/api/paste/"+id, nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp GetResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	decoded, _ := base64.RawURLEncoding.DecodeString(resp.Content)
	if string(decoded) != "hello" {
		t.Errorf("content mismatch: got %q", decoded)
	}
}

func TestGetMissing(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	req := httptest.NewRequest("GET", "/api/paste/nonexistent", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestGetExpired(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	// create expired paste
	id, _ := s.Create([]byte("expired"), "", time.Now().Add(-time.Hour))

	req := httptest.NewRequest("GET", "/api/paste/"+id, nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for expired, got %d", rec.Code)
	}
}

func TestDeleteValidToken(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	token := "secret123"
	hash := sha256.Sum256([]byte(token))
	deleteHash := hex.EncodeToString(hash[:])

	id, _ := s.Create([]byte("to delete"), deleteHash, time.Now().Add(time.Hour))

	req := httptest.NewRequest("DELETE", "/api/paste/"+id+"?token="+token, nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// verify deleted
	req2 := httptest.NewRequest("GET", "/api/paste/"+id, nil)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Error("paste should be deleted")
	}
}

func TestDeleteInvalidToken(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	token := "secret123"
	hash := sha256.Sum256([]byte(token))
	deleteHash := hex.EncodeToString(hash[:])

	id, _ := s.Create([]byte("data"), deleteHash, time.Now().Add(time.Hour))

	req := httptest.NewRequest("DELETE", "/api/paste/"+id+"?token=wrongtoken", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for invalid token, got %d", rec.Code)
	}
}

func TestRequestTooLarge(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	// create body > 1MB
	largeContent := make([]byte, 2*1024*1024)
	encoded := base64.RawURLEncoding.EncodeToString(largeContent)
	body := `{"content":"` + encoded + `"}`

	req := httptest.NewRequest("POST", "/api/paste", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	headers := map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
	}

	for header, expected := range headers {
		got := rec.Header().Get(header)
		if got == "" {
			t.Errorf("missing header %s", header)
		} else if !strings.Contains(got, expected) {
			t.Errorf("header %s: expected to contain %q, got %q", header, expected, got)
		}
	}
}

func TestIndex(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "html") {
		t.Error("expected html response")
	}
}

func TestPasteRoute(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	req := httptest.NewRequest("GET", "/p/someid", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestCreateReturnsID(t *testing.T) {
	s := testStore(t)
	srv := New(s, nil)

	body := bytes.NewBufferString(`{"content":"dGVzdA","ttl":3600}`)
	req := httptest.NewRequest("POST", "/api/paste", body)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	var resp CreateResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if len(resp.ID) != 22 {
		t.Errorf("expected 22 char ID, got %d: %s", len(resp.ID), resp.ID)
	}
}
