package route

import (
	"be-portfolio/controller"

	"github.com/gofiber/fiber/v2"
)

// SetupRoutes initializes all the application routes
func SetupRoutes(app *fiber.App) {

	// User routes
	userRoutes := app.Group("/users")
	userRoutes.Post("/register", controller.Register) // Route untuk registrasi pengguna
	userRoutes.Post("/login", controller.Login)       // Route untuk login pengguna

	userRoutes.Get("/me", controller.JWTAuth, func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"user_id":  c.Locals("user_id"),
			"username": c.Locals("username"),
			"role":     c.Locals("role"),
		})
	})
}
