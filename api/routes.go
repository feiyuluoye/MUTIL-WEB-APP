package api

import (
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
