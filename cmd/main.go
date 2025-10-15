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
	router := gin.New()
	router.Use(gin.Recovery())

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
