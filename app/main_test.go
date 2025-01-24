package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ... (Task struct remains the same)

func setupTestDB() *gorm.DB {
	host := "localhost"
	port := "5432"
	user := "postgres"
	password := "password"
	dbname := "postgres"

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Kolkata", host, user, password, dbname, port)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to test database:", err)
	}

	db.AutoMigrate(&Task{})
	return db
}

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.Default()

	router.POST("/login", login)

	protected := router.Group("/api")
	protected.Use(authMiddleware())
	{
		protected.POST("/tasks", createTask)
		protected.GET("/tasks", getAllTasks)
		protected.GET("/tasks/:id", getTask)
		protected.PUT("/tasks/:id", updateTask)
		protected.DELETE("/tasks/:id", deleteTask)
	}
	return router
}

func generateTestToken(username string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(jwtKey)
	return tokenString
}

func TestMain(m *testing.M) {
	JWT_SECRET = "dac59f7d58b92e37488f0c8c0345463d090360a7a1b6e2d39ac102faf75791b1"
	db = setupTestDB()
	jwtKey = []byte(JWT_SECRET)
	if len(jwtKey) == 0 {
		log.Fatal("JWT_SECRET environment variable is required")
	}
	code := m.Run()
	// Clean up test database after all tests
	db.Migrator().DropTable(&Task{})
	os.Exit(code)
}

func TestTaskCRUD(t *testing.T) {
	router := setupRouter()

	// Test Data
	testTask := Task{Title: "Test Task", Description: "Test Description"}
	updatedTask := Task{Title: "Updated Task", Description: "Updated Description", Completed: true}

	// Generate Test token
	token := generateTestToken("admin")

	// Test Create Task
	w := httptest.NewRecorder()
	jsonValue, _ := json.Marshal(testTask)
	req, _ := http.NewRequest("POST", "/api/tasks", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var createdTask Task
	json.Unmarshal(w.Body.Bytes(), &createdTask)
	assert.Equal(t, testTask.Title, createdTask.Title)

	// Test Get All Tasks
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/tasks", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var tasks []Task
	json.Unmarshal(w.Body.Bytes(), &tasks)
	assert.GreaterOrEqual(t, len(tasks), 1) // At least one task should be present

	// Test Get Task by ID
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/tasks/"+strconv.Itoa(int(createdTask.ID)), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var retrievedTask Task
	json.Unmarshal(w.Body.Bytes(), &retrievedTask)
	assert.Equal(t, createdTask.Title, retrievedTask.Title)

	// Test Update Task
	w = httptest.NewRecorder()
	jsonValue, _ = json.Marshal(updatedTask)
	req, _ = http.NewRequest("PUT", "/api/tasks/"+strconv.Itoa(int(createdTask.ID)), bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test Delete Task
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/api/tasks/"+strconv.Itoa(int(createdTask.ID)), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test Get Task after Deletion (should return 404)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/tasks/"+strconv.Itoa(int(createdTask.ID)), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

}

func TestAuthMiddlewareMissingToken(t *testing.T) {
	router := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/tasks", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	bodyString := w.Body.String()
	assert.Contains(t, strings.ToLower(bodyString), "authorization header is required")

}

func TestAuthMiddlewareInvalidToken(t *testing.T) {
	router := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/tasks", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	bodyString := w.Body.String()
	assert.Contains(t, strings.ToLower(bodyString), "invalid token")
}

func TestLoginRoute(t *testing.T) {
	router := setupRouter()

	w := httptest.NewRecorder()
	jsonValue, _ := json.Marshal(User{Username: "admin", Password: "admin"})
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	token, ok := response["token"]
	assert.True(t, ok)
	assert.NotEmpty(t, token)

}
