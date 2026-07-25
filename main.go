package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"admission-controller/pkg/webhook"
)

func main() {
	var certFile string
	var keyFile string
	var addr string

	flag.StringVar(&certFile, "tls-cert-file", "/etc/webhook/certs/tls.crt", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&keyFile, "tls-key-file", "/etc/webhook/certs/tls.key", "File containing the x509 private key to matching tls-cert-file.")
	flag.StringVar(&addr, "port", ":8443", "The port to listen on.")
	flag.Parse()

	// Override flags with env variables if set
	if envCert := os.Getenv("TLS_CERT_FILE"); envCert != "" {
		certFile = envCert
	}
	if envKey := os.Getenv("TLS_KEY_FILE"); envKey != "" {
		keyFile = envKey
	}
	if envPort := os.Getenv("PORT"); envPort != "" {
		addr = ":" + envPort
	}

	log.Printf("Starting Kubernetes Admission Controller Webhook server...")
	log.Printf("TLS Cert: %s", certFile)
	log.Printf("TLS Key: %s", keyFile)
	log.Printf("Listening Address: %s", addr)

	ws := webhook.NewWebhookServer()
	log.Printf("Enforce secrets blocking mode: %t", ws.EnforceBlock)

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", ws.HandleMutate)
	mux.HandleFunc("/validate", ws.HandleValidate)
	
	// Readiness and liveness probes
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Channel to listen for shutdown signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		// Run server in background
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to listen and serve TLS: %v", err)
		}
	}()

	log.Printf("Webhook server is running and ready to handle requests.")

	// Block until a signal is received
	sig := <-signalChan
	log.Printf("Received signal %s. Shutting down server gracefully...", sig)

	// Attempt graceful shutdown with 10s timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	} else {
		log.Printf("Server exited clean.")
	}
}
