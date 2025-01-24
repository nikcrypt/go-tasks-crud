package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/juju/ratelimit"
	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Task struct {
	ID          int       `json:"id"`
	Title       string    `json:"title" binding:"required,min=3"`
	Description string    `json:"description"`
	Completed   bool      `json:"completed"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type User struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

var db *gorm.DB
var jwtKey []byte // Secret key for JWT signing
var JWT_SECRET string
var limiter *ratelimit.Bucket // Rate limiter instance

func main() {
	JWT_SECRET = "dac59f7d58b92e37488f0c8c0345463d090360a7a1b6e2d39ac102faf75791b1"
	// Database connection
	// Read database connection details from environment variables
	host := "localhost"
	portStr := "5432"
	user := "postgres"
	pass := "password"
	dbname := "postgres"

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, pass, host, portStr, dbname) + "?sslmode=disable"

	var err error
	db, err = gorm.Open(postgres.Open(connStr), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// AutoMigrate will create the table if it doesn't exist
	// It will also migrate the schema if there are changes to the model
	db.AutoMigrate(&Task{})

	jwtKey = []byte(JWT_SECRET) // Load JWT secret from environment variable
	if len(jwtKey) == 0 {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	// Rate Limiting setup: 10 requests per second
	limiter = ratelimit.NewBucketWithRate(10, 10)

	// Gin setup
	router := gin.Default()

	// Public routes (e.g., login)
	router.POST("/login", login)
	router.GET("/tasks", getAllTasks)
	// Protected routes (require JWT authentication)
	protected := router.Group("/api")
	protected.Use(authMiddleware(), rateLimitMiddleware())
	{
		protected.POST("/tasks", createTask)
		protected.GET("/tasks", getAllTasks)
		protected.GET("/tasks/:id", getTask)
		protected.PUT("/tasks/:id", updateTask)
		protected.DELETE("/tasks/:id", deleteTask)
	}

	router.Run(":8080")
}

func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if limiter.TakeAvailable(1) == 0 { // Check if a token is available
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
			return
		}
		c.Next()
	}
}

func createTask(c *gin.Context) {
	var task Task
	if err := c.ShouldBindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Create(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, task)
}

func getAllTasks(c *gin.Context) {
	var tasks []Task
	if err := db.Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tasks)
}

func getTask(c *gin.Context) {
	id := c.Param("id")
	var task Task
	if err := db.First(&task, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, task)
}

func updateTask(c *gin.Context) {
	id := c.Param("id")
	var task Task
	if err := c.ShouldBindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Model(&Task{}).Where("id = ?", id).Updates(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task updated"})
}

func deleteTask(c *gin.Context) {
	id := c.Param("id")
	if err := db.Delete(&Task{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task deleted"})
}

func login(c *gin.Context) {
	// In a real application, you would validate user credentials here.
	// For this example, we'll just generate a token.

	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Basic "admin/admin" check (INSECURE - DO NOT USE IN PRODUCTION)
	if user.Username != "admin" || user.Password != "admin" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username, // Include username in claims
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})

	// Sign the token with the secret key
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}
		fmt.Println("Received token:", tokenString)

		// Remove "Bearer " prefix if it exists
		if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
			tokenString = tokenString[7:]                // Remove "bearer " (7 characters)
			tokenString = strings.TrimSpace(tokenString) // Remove leading/trailing spaces
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtKey, nil
		})

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Access claims (e.g., user_id) if needed
			fmt.Println(claims["user_id"])
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}
	}
}

func getAllTasksPaginate(c *gin.Context) {
	var tasks []Task
	var total int64

	// Pagination parameters
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "5")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid page number"})
		return
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 || pageSize > 100 { // Limit page size to prevent abuse
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid page size"})
		return
	}

	offset := (page - 1) * pageSize

	// Get total count
	db.Model(&Task{}).Count(&total)

	// Perform the query with pagination
	result := db.Offset(offset).Limit(pageSize).Find(&tasks)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tasks":       tasks,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": (total + int64(pageSize) - 1) / int64(pageSize), // Calculate total pages
	})
}
