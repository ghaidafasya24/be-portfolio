package route

import (
	"be-portfolio/controller" // Sesuaikan dengan nama package project Anda

	"github.com/gofiber/fiber/v2"
)

// SetupRoutes initializes all the application routes
func SetupRoutes(app *fiber.App) {
	// Group API routes
	api := app.Group("/api")

	// User routes
	userRoutes := api.Group("/users")
	userRoutes.Post("/register", controller.Register) // Route untuk registrasi pengguna
	userRoutes.Post("/login", controller.Login)       // Route untuk login pengguna

	// Menu routes
	// menuRoutes := api.Group("/menu")
	// // menuRoutes.Post("/", controller.JWTAuth, controller.InsertMenu)
	// menuRoutes.Post("/", controller.InsertMenu)    // Insert menu
	// menuRoutes.Get("/", controller.GetAllMenu)     // Route untuk mengambil semua menu
	// menuRoutes.Get("/:id", controller.GetMenuByID) // Route untuk mengambil menu berdasarkan ID
	// // menuRoutes.Put("/:id", controller.JWTAuth, controller.UpdateMenu)
	// menuRoutes.Put("/:id", controller.UpdateMenu) // Route untuk memperbarui menu berdasarkan ID
	// // menuRoutes.Delete("/:id", controller.JWTAuth, controller.DeleteMenu)
	// menuRoutes.Delete("/:id", controller.DeleteMenu) // Route untuk menghapus menu berdasarkan ID
}
