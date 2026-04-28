package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type Server struct {
	engine *gin.Engine
	http   *http.Server
}

func NewServer(engine *gin.Engine) *Server {
	return &Server{
		engine: engine,
		http: &http.Server{
			Handler:      engine,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}
}

func (s *Server) Start(port string) error {
	s.http.Addr = fmt.Sprintf(":%s", port)
	fmt.Println("Server started on port", port)
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	fmt.Println("Shutting down server...")
	return s.http.Shutdown(ctx)
}
