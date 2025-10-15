package api

import (
	"microservice-gateway/internal/config"
	"microservice-gateway/internal/handlers"
	"microservice-gateway/internal/middleware"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// RootHandler 返回根路径处理器
func RootHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Microservice Gateway API",
			"version": "1.0.0",
		})
	}
}

// HealthHandler 返回健康检查处理器
func HealthHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().Unix(),
		})
	}
}

// SetupRoutes 注册所有路由
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
		v1.GET("/health", HealthHandler())
	}

	// 根路径
	router.GET("/", RootHandler())
}
