package main

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"stash/internal/crypto"
)

type Config struct {
	Server string
	TTL    int
}

type CreateResponse struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expires_at"`
}

type GetResponse struct {
	Content   string `json:"content"`
	ExpiresAt string `json:"expires_at"`
}

func main() {
	cfg := loadConfig()

	serverFlag := flag.String("server", cfg.Server, "server URL")
	ttlFlag := flag.Int("ttl", cfg.TTL, "TTL in seconds")
	flag.Parse()

	if *serverFlag == "" {
		*serverFlag = "http://localhost:8080"
	}
	if *ttlFlag <= 0 {
		*ttlFlag = 3600
	}

	args := flag.Args()
	if len(args) == 0 {
		// read from stdin and create paste
		createPaste(*serverFlag, *ttlFlag)
		return
	}

	switch args[0] {
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: stash get <url>")
			os.Exit(1)
		}
		getPaste(args[1])
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: stash delete <delete-url>")
			os.Exit(1)
		}
		deletePaste(args[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		os.Exit(1)
	}
}

func loadConfig() Config {
	cfg := Config{}
	home, err := os.UserHomeDir()
	if err != nil {
		return cfg
	}

	f, err := os.Open(filepath.Join(home, ".stashrc"))
	if err != nil {
		return cfg
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "server=") {
			cfg.Server = strings.TrimPrefix(line, "server=")
		}
		if strings.HasPrefix(line, "ttl=") {
			fmt.Sscanf(strings.TrimPrefix(line, "ttl="), "%d", &cfg.TTL)
		}
	}
	return cfg
}

func createPaste(server string, ttl int) {
	// read stdin
	plaintext, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		os.Exit(1)
	}

	// trim trailing newline
	plaintext = bytes.TrimSuffix(plaintext, []byte("\n"))

	// generate key
	key, err := crypto.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating key: %v\n", err)
		os.Exit(1)
	}

	// encrypt
	blob, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encrypting: %v\n", err)
		os.Exit(1)
	}

	// generate delete token
	deleteToken := make([]byte, 16)
	if _, err := cryptorand.Read(deleteToken); err != nil {
		fmt.Fprintf(os.Stderr, "error generating token: %v\n", err)
		os.Exit(1)
	}
	deleteTokenStr := crypto.EncodeKey(deleteToken)

	// hash delete token
	hash := sha256.Sum256([]byte(deleteTokenStr))
	deleteHash := hex.EncodeToString(hash[:])

	// send to server
	reqBody := map[string]interface{}{
		"content":           crypto.EncodeBlob(blob),
		"ttl":               ttl,
		"delete_token_hash": deleteHash,
	}
	body, _ := json.Marshal(reqBody)

	resp, err := http.Post(server+"/api/paste", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error sending request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "server error: %s\n", resp.Status)
		os.Exit(1)
	}

	var createResp CreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		fmt.Fprintf(os.Stderr, "error decoding response: %v\n", err)
		os.Exit(1)
	}

	keyStr := crypto.EncodeKey(key)
	pasteURL := server + "/p/" + createResp.ID + "#v1:" + keyStr
	deleteURL := server + "/api/paste/" + createResp.ID + "?token=" + deleteTokenStr

	fmt.Printf("paste: %s\n", pasteURL)
	fmt.Printf("delete: %s\n", deleteURL)
}

func getPaste(pasteURL string) {
	// parse URL
	u, err := url.Parse(pasteURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid URL: %v\n", err)
		os.Exit(1)
	}

	// extract ID and key
	path := u.Path
	if !strings.HasPrefix(path, "/p/") {
		fmt.Fprintln(os.Stderr, "invalid paste URL")
		os.Exit(1)
	}
	id := strings.TrimPrefix(path, "/p/")

	fragment := u.Fragment
	if !strings.HasPrefix(fragment, "v1:") {
		fmt.Fprintln(os.Stderr, "invalid paste URL (missing key)")
		os.Exit(1)
	}
	keyStr := strings.TrimPrefix(fragment, "v1:")

	key, err := crypto.DecodeKey(keyStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid key: %v\n", err)
		os.Exit(1)
	}

	// fetch from server
	server := u.Scheme + "://" + u.Host
	resp, err := http.Get(server + "/api/paste/" + id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching paste: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Fprintln(os.Stderr, "paste not found or expired")
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "server error: %s\n", resp.Status)
		os.Exit(1)
	}

	var getResp GetResponse
	if err := json.NewDecoder(resp.Body).Decode(&getResp); err != nil {
		fmt.Fprintf(os.Stderr, "error decoding response: %v\n", err)
		os.Exit(1)
	}

	// decode and decrypt
	blob, err := crypto.DecodeBlob(getResp.Content)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding blob: %v\n", err)
		os.Exit(1)
	}

	plaintext, err := crypto.Decrypt(blob, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decryption failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(string(plaintext))
}

func deletePaste(deleteURL string) {
	req, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid URL: %v\n", err)
		os.Exit(1)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		fmt.Println("deleted")
	} else if resp.StatusCode == http.StatusNotFound {
		fmt.Fprintln(os.Stderr, "not found or invalid token")
		os.Exit(1)
	} else {
		fmt.Fprintf(os.Stderr, "error: %s\n", resp.Status)
		os.Exit(1)
	}
}

