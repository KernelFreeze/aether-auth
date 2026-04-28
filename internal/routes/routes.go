package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	handlers "github.com/hokamsingh/go-backend-template/internal/handlers/user"
	"github.com/hokamsingh/go-backend-template/internal/middleware"
	"github.com/hokamsingh/go-backend-template/internal/repository"
	"github.com/hokamsingh/go-backend-template/internal/service"
	"gorm.io/gorm"
)

// Route defines the structure for dynamic routing
type Route struct {
	Method      string
	Path        string
	HandlerFunc gin.HandlerFunc
}

// Controller defines the structure for a controller with routes
type Controller struct {
	Routes []Route
}

// SetupRouter dynamically sets up routes
func SetupRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode("release")

	r := gin.Default()
	r.Use(middleware.CORS())
	r.Use(middleware.Logger())

	// Load HTML templates
	r.LoadHTMLGlob("templates/*")

	// Serve static files
	r.Static("/static", "./static")

	// Serve index.html at "/"
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "Welcome to Go Backend",
		})
	})

	// Initialize Repositories
	userRepo := repository.NewUserRepository(db)

	// Initialize Services
	userService := service.NewUserService(userRepo)

	// Initialize Controllers
	userController := handlers.NewUserController(userService)

	// Define controllers and their routes
	controllers := map[string]Controller{
		"user": {
			Routes: []Route{
				{"GET", "/users/:id", userController.GetUserByID},
				{"POST", "/users", userController.CreateUser},
			},
		},
	}

	// Register all routes dynamically
	api := r.Group("/api")
	for _, controller := range controllers {
		for _, route := range controller.Routes {
			api.Handle(route.Method, route.Path, route.HandlerFunc)
		}
	}

	return r
}
