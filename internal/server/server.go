// Package server is a thin wrapper over net/http with graceful shutdown
// integration. It does not depend on Gin directly so it can host any
// http.Handler.
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Options tunes the HTTP server's per-request limits.
type Options struct {
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Server wraps an http.Handler with sensible defaults for a public listener.
type Server struct {
	http *http.Server
}

// NewServer builds a Server from the given handler and options.
func NewServer(handler http.Handler, opts Options) *Server {
	read := opts.ReadTimeout
	if read <= 0 {
		read = 5 * time.Second
	}
	write := opts.WriteTimeout
	if write <= 0 {
		write = 10 * time.Second
	}
	return &Server{
		http: &http.Server{
			Handler:      handler,
			ReadTimeout:  read,
			WriteTimeout: write,
		},
	}
}

// Start binds the listener on the given port and serves until Shutdown is
// called or the listener errors out.
func (s *Server) Start(port string) error {
	s.http.Addr = fmt.Sprintf(":%s", port)
	return s.http.ListenAndServe()
}

// Shutdown gracefully stops the server, draining in-flight requests up to
// the deadline encoded on the context.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
