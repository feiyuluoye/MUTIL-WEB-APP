package routers

import (
	"microservice-gateway/config"
	"microservice-gateway/internal/api"
	internalhandlers "microservice-gateway/internal/handlers"
	"microservice-gateway/middleware"

	"github.com/gin-gonic/gin"
)

// SetupRoutes 将路由注册到 provided router
func SetupRoutes(router *gin.Engine, cfg *config.Config, serviceHandler *internalhandlers.ServiceHandler) {
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
		v1.GET("/health", api.HealthHandler())
	}

	// 根路径
	router.GET("/", api.RootHandler())
}
