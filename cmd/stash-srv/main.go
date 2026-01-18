package main

import (
	"context"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"stash/internal/server"
	"stash/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dbPath := flag.String("db", "./stash.db", "database path")
	flag.Parse()

	s, err := store.New(*dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer s.Close()

	staticFS, _ := fs.Sub(server.StaticFS, "static")
	srv := server.New(s, http.FS(staticFS))

	httpSrv := &http.Server{
		Addr:    *addr,
		Handler: srv,
	}

	// cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if n, err := s.Cleanup(); err != nil {
					log.Printf("cleanup error: %v", err)
				} else if n > 0 {
					log.Printf("cleaned up %d expired pastes", n)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("listening on %s", *addr)
	if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
