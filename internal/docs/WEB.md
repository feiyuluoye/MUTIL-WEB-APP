## Go Gin微服务Web框架

### 项目结构

```
microservice-gateway/
├── main.go
├── go.mod
├── config/
│   └── config.go
├── models/
│   └── models.go
├── handlers/
│   └── service_handler.go
├── middleware/
│   └── middleware.go
├── registry/
│   └── service_registry.go
├── database/
│   └── sqlite.go
├── api/
│   └── routes.go
└── utils/
    └── response.go
```

### 核心代码实现

#### 1. 配置文件 (config/config.go)

```go
package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	ServerPort    string
	DBPath        string
	JWTSecret     string
	EnableAuth    bool
	LogLevel      string
	MaxServices   int
	HealthCheckInterval int
}

func Load() *Config {
	return &Config{
		ServerPort:    getEnv("SERVER_PORT", "8080"),
		DBPath:        getEnv("DB_PATH", "./services.db"),
		JWTSecret:     getEnv("JWT_SECRET", "your-secret-key"),
		EnableAuth:    getEnvAsBool("ENABLE_AUTH", false),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		MaxServices:   getEnvAsInt("MAX_SERVICES", 100),
		HealthCheckInterval: getEnvAsInt("HEALTH_CHECK_INTERVAL", 30),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}
```

#### 2. 数据模型 (models/models.go)

```go
package models

import (
	"time"
)

// ServiceInfo 微服务信息
type ServiceInfo struct {
	ID           string    `json:"id" gorm:"primaryKey"`
	Name         string    `json:"name" gorm:"not null;index"`
	Version      string    `json:"version"`
	Description  string    `json:"description"`
	BaseURL      string    `json:"base_url" gorm:"not null"`
	HealthURL    string    `json:"health_url"`
	Status       string    `json:"status" gorm:"default:'unknown'"` // unknown, healthy, unhealthy
	Metadata     string    `json:"metadata"` // JSON格式的元数据
	LastHealthCheck time.Time `json:"last_health_check"`
	RegisteredAt time.Time `json:"registered_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ServiceRegistration 服务注册请求
type ServiceRegistration struct {
	Name        string            `json:"name" binding:"required"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	BaseURL     string            `json:"base_url" binding:"required,url"`
	HealthURL   string            `json:"health_url"`
	Metadata    map[string]string `json:"metadata"`
}

// ServiceResponse 服务响应
type ServiceResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// HealthCheckRequest 健康检查请求
type HealthCheckRequest struct {
	ServiceID string `json:"service_id" binding:"required"`
}

// ServiceStats 服务统计
type ServiceStats struct {
	TotalServices   int `json:"total_services"`
	HealthyServices int `json:"healthy_services"`
	UnhealthyServices int `json:"unhealthy_services"`
}
```

#### 3. 数据库层 (database/sqlite.go)

```go
package database

import (
	"fmt"
	"microservice-gateway/models"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func InitDB(dbPath string) error {
	var err error
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to connect database: %v", err)
	}

	// 自动迁移表结构
	err = DB.AutoMigrate(&models.ServiceInfo{})
	if err != nil {
		return fmt.Errorf("failed to migrate database: %v", err)
	}

	return nil
}

func CreateService(service *models.ServiceInfo) error {
	service.RegisteredAt = time.Now()
	service.UpdatedAt = time.Now()
	return DB.Create(service).Error
}

func GetServiceByID(id string) (*models.ServiceInfo, error) {
	var service models.ServiceInfo
	err := DB.Where("id = ?", id).First(&service).Error
	return &service, err
}

func GetServiceByName(name string) (*models.ServiceInfo, error) {
	var service models.ServiceInfo
	err := DB.Where("name = ?", name).First(&service).Error
	return &service, err
}

func GetAllServices() ([]models.ServiceInfo, error) {
	var services []models.ServiceInfo
	err := DB.Order("registered_at DESC").Find(&services).Error
	return services, err
}

func UpdateService(service *models.ServiceInfo) error {
	service.UpdatedAt = time.Now()
	return DB.Save(service).Error
}

func UpdateServiceStatus(id string, status string) error {
	return DB.Model(&models.ServiceInfo{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"status": status,
			"last_health_check": time.Now(),
			"updated_at": time.Now(),
		}).Error
}

func DeleteService(id string) error {
	return DB.Where("id = ?", id).Delete(&models.ServiceInfo{}).Error
}

func GetServiceStats() (*models.ServiceStats, error) {
	var stats models.ServiceStats
	
	var total int64
	DB.Model(&models.ServiceInfo{}).Count(&total)
	stats.TotalServices = int(total)
	
	var healthy int64
	DB.Model(&models.ServiceInfo{}).Where("status = ?", "healthy").Count(&healthy)
	stats.HealthyServices = int(healthy)
	
	stats.UnhealthyServices = stats.TotalServices - stats.HealthyServices
	
	return &stats, nil
}
```

#### 4. 服务注册中心 (registry/service_registry.go)

```go
package registry

import (
	"encoding/json"
	"fmt"
	"microservice-gateway/database"
	"microservice-gateway/models"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type ServiceRegistry struct {
	healthCheckInterval time.Duration
}

func NewServiceRegistry(healthCheckInterval int) *ServiceRegistry {
	return &ServiceRegistry{
		healthCheckInterval: time.Duration(healthCheckInterval) * time.Second,
	}
}

// RegisterService 注册微服务
func (sr *ServiceRegistry) RegisterService(reg models.ServiceRegistration) (*models.ServiceInfo, error) {
	// 检查服务是否已存在
	existingService, _ := database.GetServiceByName(reg.Name)
	if existingService != nil {
		// 更新现有服务
		existingService.Version = reg.Version
		existingService.Description = reg.Description
		existingService.BaseURL = reg.BaseURL
		existingService.HealthURL = reg.HealthURL
		existingService.Status = "unknown"
		
		// 处理元数据
		if reg.Metadata != nil {
			metadata, _ := json.Marshal(reg.Metadata)
			existingService.Metadata = string(metadata)
		}
		
		err := database.UpdateService(existingService)
		if err != nil {
			return nil, fmt.Errorf("failed to update service: %v", err)
		}
		
		return existingService, nil
	}
	
	// 创建新服务
	metadataStr := ""
	if reg.Metadata != nil {
		metadata, _ := json.Marshal(reg.Metadata)
		metadataStr = string(metadata)
	}
	
	service := &models.ServiceInfo{
		ID:          uuid.New().String(),
		Name:        reg.Name,
		Version:     reg.Version,
		Description: reg.Description,
		BaseURL:     reg.BaseURL,
		HealthURL:   reg.HealthURL,
		Status:      "unknown",
		Metadata:    metadataStr,
	}
	
	err := database.CreateService(service)
	if err != nil {
		return nil, fmt.Errorf("failed to register service: %v", err)
	}
	
	return service, nil
}

// DeregisterService 注销服务
func (sr *ServiceRegistry) DeregisterService(serviceID string) error {
	return database.DeleteService(serviceID)
}

// HealthCheck 健康检查
func (sr *ServiceRegistry) HealthCheck(serviceID string) error {
	service, err := database.GetServiceByID(serviceID)
	if err != nil {
		return fmt.Errorf("service not found: %v", err)
	}
	
	if service.HealthURL == "" {
		return database.UpdateServiceStatus(serviceID, "unknown")
	}
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(service.HealthURL)
	if err != nil {
		return database.UpdateServiceStatus(serviceID, "unhealthy")
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return database.UpdateServiceStatus(serviceID, "healthy")
	} else {
		return database.UpdateServiceStatus(serviceID, "unhealthy")
	}
}

// StartHealthChecks 启动定时健康检查
func (sr *ServiceRegistry) StartHealthChecks() {
	ticker := time.NewTicker(sr.healthCheckInterval)
	
	go func() {
		for range ticker.C {
			sr.performHealthChecks()
		}
	}()
}

func (sr *ServiceRegistry) performHealthChecks() {
	services, err := database.GetAllServices()
	if err != nil {
		return
	}
	
	for _, service := range services {
		go sr.HealthCheck(service.ID)
	}
}
```

#### 5. 处理器 (handlers/service_handler.go)

```go
package handlers

import (
	"microservice-gateway/database"
	"microservice-gateway/models"
	"microservice-gateway/registry"
	"microservice-gateway/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ServiceHandler struct {
	registry *registry.ServiceRegistry
}

func NewServiceHandler(registry *registry.ServiceRegistry) *ServiceHandler {
	return &ServiceHandler{
		registry: registry,
	}
}

// RegisterService 注册微服务
func (h *ServiceHandler) RegisterService(c *gin.Context) {
	var reg models.ServiceRegistration
	if err := c.ShouldBindJSON(&reg); err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request payload")
		return
	}
	
	service, err := h.registry.RegisterService(reg)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	
	utils.SuccessResponse(c, "Service registered successfully", service)
}

// DeregisterService 注销服务
func (h *ServiceHandler) DeregisterService(c *gin.Context) {
	serviceID := c.Param("id")
	
	err := h.registry.DeregisterService(serviceID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	
	utils.SuccessResponse(c, "Service deregistered successfully", nil)
}

// GetService 获取服务信息
func (h *ServiceHandler) GetService(c *gin.Context) {
	serviceID := c.Param("id")
	
	service, err := database.GetServiceByID(serviceID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Service not found")
		return
	}
	
	utils.SuccessResponse(c, "Service found", service)
}

// GetAllServices 获取所有服务
func (h *ServiceHandler) GetAllServices(c *gin.Context) {
	services, err := database.GetAllServices()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	
	utils.SuccessResponse(c, "Services retrieved successfully", services)
}

// HealthCheck 手动健康检查
func (h *ServiceHandler) HealthCheck(c *gin.Context) {
	serviceID := c.Param("id")
	
	err := h.registry.HealthCheck(serviceID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	
	service, _ := database.GetServiceByID(serviceID)
	utils.SuccessResponse(c, "Health check completed", service)
}

// GetServiceStats 获取服务统计
func (h *ServiceHandler) GetServiceStats(c *gin.Context) {
	stats, err := database.GetServiceStats()
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	
	utils.SuccessResponse(c, "Stats retrieved successfully", stats)
}

// ServiceDiscovery 服务发现
func (h *ServiceHandler) ServiceDiscovery(c *gin.Context) {
	serviceName := c.Query("name")
	
	if serviceName == "" {
		utils.ErrorResponse(c, http.StatusBadRequest, "Service name is required")
		return
	}
	
	service, err := database.GetServiceByName(serviceName)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Service not found")
		return
	}
	
	utils.SuccessResponse(c, "Service found", service)
}
```

#### 6. 中间件 (middleware/middleware.go)

```go
package middleware

import (
	"microservice-gateway/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// CORS 跨域中间件
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	}
}

// Logger 日志中间件
func Logger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("[%s] - %s \"%s %s %s %d %s \"%s\" %s\"\n",
			param.TimeStamp.Format(time.RFC1123),
			param.ClientIP,
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// AuthMiddleware JWT认证中间件
func AuthMiddleware(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Authorization header required")
			c.Abort()
			return
		}
		
		// 移除 "Bearer " 前缀
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}
		
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})
		
		if err != nil || !token.Valid {
			utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid token")
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// RateLimit 限流中间件
func RateLimit(requestsPerMinute int) gin.HandlerFunc {
	limiter := make(map[string][]time.Time)
	
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()
		minuteAgo := now.Add(-time.Minute)
		
		// 清理过期的请求记录
		if requests, exists := limiter[clientIP]; exists {
			var validRequests []time.Time
			for _, reqTime := range requests {
				if reqTime.After(minuteAgo) {
					validRequests = append(validRequests, reqTime)
				}
			}
			limiter[clientIP] = validRequests
		}
		
		// 检查是否超过限制
		if len(limiter[clientIP]) >= requestsPerMinute {
			utils.ErrorResponse(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}
		
		// 记录本次请求
		limiter[clientIP] = append(limiter[clientIP], now)
		c.Next()
	}
}
```

#### 7. 工具函数 (utils/response.go)

```go
package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func SuccessResponse(c *gin.Context, message string, data interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": message,
		"data":    data,
	})
}

func ErrorResponse(c *gin.Context, statusCode int, errorMessage string) {
	c.JSON(statusCode, gin.H{
		"success": false,
		"error":   errorMessage,
	})
}

func CreatedResponse(c *gin.Context, message string, data interface{}) {
	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": message,
		"data":    data,
	})
}
```

#### 8. 路由配置 (api/routes.go)

```go
package api

import (
	"microservice-gateway/config"
	"microservice-gateway/handlers"
	"microservice-gateway/middleware"
	"microservice-gateway/registry"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine, cfg *config.Config, serviceHandler *handlers.ServiceHandler) {
	// 全局中间件
	router.Use(middleware.CORS())
	router.Use(middleware.Logger())
	router.Use(middleware.RateLimit(60)) // 每分钟60个请求
	
	// API v1 路由组
	v1 := router.Group("/api/v1")
	{
		// 服务注册相关路由
		services := v1.Group("/services")
		{
			services.POST("/register", serviceHandler.RegisterService)
			services.GET("", serviceHandler.GetAllServices)
			services.GET("/stats", serviceHandler.GetServiceStats)
			services.GET("/discover", serviceHandler.ServiceDiscovery)
			
			// 需要认证的路由
			authRequired := services.Group("")
			if cfg.EnableAuth {
				authRequired.Use(middleware.AuthMiddleware(cfg.JWTSecret))
			}
			{
				authRequired.GET("/:id", serviceHandler.GetService)
				authRequired.DELETE("/:id", serviceHandler.DeregisterService)
				authRequired.POST("/:id/health-check", serviceHandler.HealthCheck)
			}
		}
		
		// 健康检查端点
		v1.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"status": "healthy",
				"timestamp": time.Now().Unix(),
			})
		})
	}
	
	// 根路径
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Microservice Gateway API",
			"version": "1.0.0",
		})
	})
}
```

#### 9. 主程序 (main.go)

```go
package main

import (
	"log"
	"microservice-gateway/api"
	"microservice-gateway/config"
	"microservice-gateway/database"
	"microservice-gateway/handlers"
	"microservice-gateway/registry"

	"github.com/gin-gonic/gin"
)

func main() {
	// 加载配置
	cfg := config.Load()
	
	// 初始化数据库
	err := database.InitDB(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	
	// 初始化服务注册中心
	serviceRegistry := registry.NewServiceRegistry(cfg.HealthCheckInterval)
	serviceRegistry.StartHealthChecks()
	
	// 初始化处理器
	serviceHandler := handlers.NewServiceHandler(serviceRegistry)
	
	// 设置Gin模式
	if cfg.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	
	// 创建Gin路由
	router := gin.Default()
	
	// 设置路由
	api.SetupRoutes(router, cfg, serviceHandler)
	
	// 启动服务器
	log.Printf("Server starting on port %s", cfg.ServerPort)
	log.Printf("Database path: %s", cfg.DBPath)
	log.Printf("Health check interval: %d seconds", cfg.HealthCheckInterval)
	
	if err := router.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```

#### 10. Go模块配置 (go.mod)

```go
module microservice-gateway

go 1.19

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/google/uuid v1.3.0
	gorm.io/driver/sqlite v1.5.0
	gorm.io/gorm v1.25.0
)
```

### 使用示例

#### 注册微服务

```bash
curl -X POST http://localhost:8080/api/v1/services/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "user-service",
    "version": "1.0.0",
    "description": "User management service",
    "base_url": "http://localhost:8081",
    "health_url": "http://localhost:8081/health",
    "metadata": {
      "environment": "production",
      "team": "backend"
    }
  }'
```

#### 发现服务

```bash
curl "http://localhost:8080/api/v1/services/discover?name=user-service"
```

#### 获取所有服务

```bash
curl http://localhost:8080/api/v1/services
```
