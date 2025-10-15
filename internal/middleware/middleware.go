package middleware

import (
	"fmt"
	"microservice-gateway/internal/utils"
	"net/http"
	"sync"
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

// RateLimit 简单限流中间件（每客户端）
func RateLimit(requestsPerMinute int) gin.HandlerFunc {
	type clientInfo struct {
		times []time.Time
	}
	limiter := make(map[string]*clientInfo)
	var mu sync.Mutex

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()
		minuteAgo := now.Add(-time.Minute)

		mu.Lock()
		ci, exists := limiter[clientIP]
		if !exists {
			ci = &clientInfo{}
			limiter[clientIP] = ci
		}

		// 清理过期
		var valid []time.Time
		for _, t := range ci.times {
			if t.After(minuteAgo) {
				valid = append(valid, t)
			}
		}
		ci.times = valid

		if len(ci.times) >= requestsPerMinute {
			mu.Unlock()
			utils.ErrorResponse(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}

		ci.times = append(ci.times, now)
		mu.Unlock()

		c.Next()
	}
}
