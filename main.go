package main

import (
	// "be-portfolio/config"
	// "be-portfolio/routes"
	"log"
	"os"

	"github.com/ghaidafasya24/be-portfolio/config"
	route "github.com/ghaidafasya24/be-portfolio/routes"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func main() {
	// Load environment variables
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000" // Default port jika PORT tidak diset
	}

	// Create a new Fiber app
	app := fiber.New()

	// Middleware untuk logging
	app.Use(logger.New())

	// Middleware untuk CORS
	app.Use(cors.New(config.Cors))

	// Setup routes
	route.SetupRoutes(app)

	// Start the server
	log.Printf("🚀 Server is running on http://localhost:%s", port)
	log.Fatal(app.Listen(":" + port))
}
