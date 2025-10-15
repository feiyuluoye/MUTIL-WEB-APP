## 第三方服务注册流程设计

### 注册流程图
```
第三方APP → 认证授权 → 服务注册 → 端点配置 → 代理设置 → 服务发现
```

### 扩展数据模型 (models/third_party.go)

```go
package models

import "time"

// ThirdPartyApp 第三方应用信息
type ThirdPartyApp struct {
    ID           string    `json:"id" gorm:"primaryKey"`
    AppName      string    `json:"app_name" gorm:"uniqueIndex;not null"`
    AppID        string    `json:"app_id" gorm:"uniqueIndex;not null"`
    AppSecret    string    `json:"app_secret" gorm:"not null"`
    Vendor       string    `json:"vendor"` // 供应商名称
    ContactEmail string    `json:"contact_email"`
    Description  string    `json:"description"`
    Status       string    `json:"status" gorm:"default:'pending'"` // pending, active, suspended
    APIKey       string    `json:"api_key" gorm:"uniqueIndex"`
    WebhookURL   string    `json:"webhook_url"` // 用于通知第三方
    RateLimit    int       `json:"rate_limit" gorm:"default:1000"` // 每分钟请求限制
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}

// ThirdPartyRegistration 第三方注册请求
type ThirdPartyRegistration struct {
    AppName      string            `json:"app_name" binding:"required"`
    Vendor       string            `json:"vendor" binding:"required"`
    ContactEmail string            `json:"contact_email" binding:"required,email"`
    Description  string            `json:"description"`
    BaseURL      string            `json:"base_url" binding:"required,url"`
    HealthURL    string            `json:"health_url"`
    WebhookURL   string            `json:"webhook_url"`
    Metadata     map[string]string `json:"metadata"`
    RequiredAPIs []string          `json:"required_apis"` // 需要访问的API列表
}

// ThirdPartyAuth 第三方认证信息
type ThirdPartyAuth struct {
    AppID     string `json:"app_id" binding:"required"`
    AppSecret string `json:"app_secret" binding:"required"`
}

// APIEndpoint 第三方API端点配置
type APIEndpoint struct {
    ID              string    `json:"id" gorm:"primaryKey"`
    AppID           string    `json:"app_id" gorm:"not null;index"`
    Path            string    `json:"path" gorm:"not null"` // 如 /api/v1/users
    Method          string    `json:"method" gorm:"not null"` // GET, POST, PUT, DELETE
    TargetURL       string    `json:"target_url" gorm:"not null"` // 实际后端URL
    Description     string    `json:"description"`
    RateLimit       int       `json:"rate_limit"` // 单独限制
    AuthRequired    bool      `json:"auth_required" gorm:"default:true"`
    Timeout         int       `json:"timeout" gorm:"default:30"` // 超时时间(秒)
    CreatedAt       time.Time `json:"created_at"`
}
```

## 2. 第三方注册处理器 (handlers/third_party_handler.go)

```go
package handlers

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "microservice-gateway/database"
    "microservice-gateway/models"
    "microservice-gateway/registry"
    "microservice-gateway/utils"
    "net/http"
    "regexp"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
)

type ThirdPartyHandler struct {
    registry *registry.ServiceRegistry
}

func NewThirdPartyHandler(registry *registry.ServiceRegistry) *ThirdPartyHandler {
    return &ThirdPartyHandler{
        registry: registry,
    }
}

// RegisterThirdParty 注册第三方应用
func (h *ThirdPartyHandler) RegisterThirdParty(c *gin.Context) {
    var req models.ThirdPartyRegistration
    if err := c.ShouldBindJSON(&req); err != nil {
        utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request payload: "+err.Error())
        return
    }

    // 验证应用名称格式
    if !isValidAppName(req.AppName) {
        utils.ErrorResponse(c, http.StatusBadRequest, "App name can only contain letters, numbers, and hyphens")
        return
    }

    // 生成应用凭证
    appID := generateAppID(req.Vendor, req.AppName)
    appSecret := generateAppSecret()
    apiKey := generateAPIKey()

    // 创建第三方应用记录
    thirdPartyApp := &models.ThirdPartyApp{
        ID:           uuid.New().String(),
        AppName:      req.AppName,
        AppID:        appID,
        AppSecret:    appSecret,
        Vendor:       req.Vendor,
        ContactEmail: req.ContactEmail,
        Description:  req.Description,
        Status:       "active",
        APIKey:       apiKey,
        WebhookURL:   req.WebhookURL,
        RateLimit:    1000, // 默认限制
        CreatedAt:    time.Now(),
        UpdatedAt:    time.Now(),
    }

    // 保存到数据库
    if err := database.CreateThirdPartyApp(thirdPartyApp); err != nil {
        utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to register app: "+err.Error())
        return
    }

    // 注册为微服务
    serviceReg := models.ServiceRegistration{
        Name:        fmt.Sprintf("thirdparty-%s", req.AppName),
        Version:     "1.0.0",
        Description: req.Description,
        BaseURL:     req.BaseURL,
        HealthURL:   req.HealthURL,
        Metadata: map[string]string{
            "type":        "third_party",
            "vendor":      req.Vendor,
            "app_id":      appID,
            "contact":     req.ContactEmail,
        },
    }

    service, err := h.registry.RegisterService(serviceReg)
    if err != nil {
        // 回滚：删除已创建的第三方应用记录
        database.DeleteThirdPartyApp(thirdPartyApp.ID)
        utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to register service: "+err.Error())
        return
    }

    // 配置默认API端点
    if err := h.setupDefaultEndpoints(appID, req.BaseURL, req.RequiredAPIs); err != nil {
        // 记录错误但不中断注册流程
        fmt.Printf("Warning: Failed to setup default endpoints: %v\n", err)
    }

    // 发送注册成功响应
    response := gin.H{
        "app_id":     appID,
        "app_secret": appSecret, // 只在创建时返回一次
        "api_key":    apiKey,
        "service_id": service.ID,
        "message":    "Third-party app registered successfully",
        "next_steps": []string{
            "Store the app_secret securely - it won't be shown again",
            "Use the api_key for making requests to the gateway",
            "Configure your API endpoints using the management API",
        },
    }

    utils.CreatedResponse(c, "Third-party app registered successfully", response)
}

// AuthenticateThirdParty 第三方应用认证
func (h *ThirdPartyHandler) AuthenticateThirdParty(c *gin.Context) {
    var auth models.ThirdPartyAuth
    if err := c.ShouldBindJSON(&auth); err != nil {
        utils.ErrorResponse(c, http.StatusBadRequest, "Invalid authentication data")
        return
    }

    app, err := database.GetThirdPartyAppByCredentials(auth.AppID, auth.AppSecret)
    if err != nil {
        utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid app credentials")
        return
    }

    if app.Status != "active" {
        utils.ErrorResponse(c, http.StatusForbidden, "App is not active")
        return
    }

    // 生成访问令牌
    token, err := h.generateAccessToken(app)
    if err != nil {
        utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to generate token")
        return
    }

    utils.SuccessResponse(c, "Authentication successful", gin.H{
        "access_token": token,
        "token_type":   "Bearer",
        "expires_in":   3600, // 1小时
        "app_id":       app.AppID,
        "app_name":     app.AppName,
    })
}

// AddAPIEndpoint 添加API端点
func (h *ThirdPartyHandler) AddAPIEndpoint(c *gin.Context) {
    appID := c.Param("app_id")
    
    var endpoint models.APIEndpoint
    if err := c.ShouldBindJSON(&endpoint); err != nil {
        utils.ErrorResponse(c, http.StatusBadRequest, "Invalid endpoint data")
        return
    }

    // 验证应用权限
    if !h.verifyAppOwnership(c, appID) {
        utils.ErrorResponse(c, http.StatusForbidden, "Access denied")
        return
    }

    endpoint.ID = uuid.New().String()
    endpoint.AppID = appID
    endpoint.CreatedAt = time.Now()

    if err := database.CreateAPIEndpoint(&endpoint); err != nil {
        utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to create endpoint")
        return
    }

    utils.CreatedResponse(c, "API endpoint added successfully", endpoint)
}

// GetAppEndpoints 获取应用的所有端点
func (h *ThirdPartyHandler) GetAppEndpoints(c *gin.Context) {
    appID := c.Param("app_id")
    
    if !h.verifyAppOwnership(c, appID) {
        utils.ErrorResponse(c, http.StatusForbidden, "Access denied")
        return
    }

    endpoints, err := database.GetEndpointsByAppID(appID)
    if err != nil {
        utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get endpoints")
        return
    }

    utils.SuccessResponse(c, "Endpoints retrieved successfully", endpoints)
}

// 辅助函数
func isValidAppName(name string) bool {
    matched, _ := regexp.MatchString("^[a-zA-Z0-9-]+$", name)
    return matched && len(name) >= 3 && len(name) <= 50
}

func generateAppID(vendor, appName string) string {
    vendorClean := strings.ToLower(strings.ReplaceAll(vendor, " ", "-"))
    appNameClean := strings.ToLower(strings.ReplaceAll(appName, " ", "-"))
    return fmt.Sprintf("%s-%s-%s", vendorClean, appNameClean, uuid.New().String()[:8])
}

func generateAppSecret() string {
    bytes := make([]byte, 32)
    rand.Read(bytes)
    return hex.EncodeToString(bytes)
}

func generateAPIKey() string {
    bytes := make([]byte, 16)
    rand.Read(bytes)
    return "sk_" + hex.EncodeToString(bytes)
}

func (h *ThirdPartyHandler) setupDefaultEndpoints(appID, baseURL string, requiredAPIs []string) error {
    // 默认的健康检查端点
    healthEndpoint := &models.APIEndpoint{
        ID:         uuid.New().String(),
        AppID:      appID,
        Path:       "/health",
        Method:     "GET",
        TargetURL:  baseURL + "/health",
        Description: "Health check endpoint",
        AuthRequired: false,
        Timeout:    5,
    }

    return database.CreateAPIEndpoint(healthEndpoint)
}

func (h *ThirdPartyHandler) verifyAppOwnership(c *gin.Context, appID string) bool {
    // 从上下文获取认证信息（在中间件中设置）
    authAppID, exists := c.Get("app_id")
    if !exists {
        return false
    }
    return authAppID == appID
}

func (h *ThirdPartyHandler) generateAccessToken(app *models.ThirdPartyApp) (string, error) {
    // 使用JWT生成访问令牌
    // 这里简化实现，实际应该使用完整的JWT
    token := fmt.Sprintf("tkn_%s_%s", app.AppID, generateAppSecret()[:16])
    return token, nil
}
```

## 3. 代理中间件 (middleware/proxy.go)

```go
package middleware

import (
    "microservice-gateway/database"
    "microservice-gateway/utils"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
)

// ThirdPartyAuth 第三方认证中间件
func ThirdPartyAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        apiKey := c.GetHeader("X-API-Key")
        
        var appID string
        
        // 支持Bearer Token和API Key两种方式
        if strings.HasPrefix(authHeader, "Bearer ") {
            token := strings.TrimPrefix(authHeader, "Bearer ")
            app, err := database.GetThirdPartyAppByToken(token)
            if err != nil {
                utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid token")
                c.Abort()
                return
            }
            appID = app.AppID
        } else if apiKey != "" {
            app, err := database.GetThirdPartyAppByAPIKey(apiKey)
            if err != nil {
                utils.ErrorResponse(c, http.StatusUnauthorized, "Invalid API key")
                c.Abort()
                return
            }
            appID = app.AppID
        } else {
            utils.ErrorResponse(c, http.StatusUnauthorized, "Authentication required")
            c.Abort()
            return
        }

        // 检查应用状态
        app, _ := database.GetThirdPartyAppByID(appID)
        if app.Status != "active" {
            utils.ErrorResponse(c, http.StatusForbidden, "App is not active")
            c.Abort()
            return
        }

        // 检查速率限制
        if !checkRateLimit(appID, app.RateLimit) {
            utils.ErrorResponse(c, http.StatusTooManyRequests, "Rate limit exceeded")
            c.Abort()
            return
        }

        // 将应用信息存入上下文
        c.Set("app_id", appID)
        c.Set("app_info", app)
        c.Next()
    }
}

// ProxyMiddleware 代理中间件
func ProxyMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // 提取路径中的服务标识
        path := c.Request.URL.Path
        parts := strings.Split(path, "/")
        
        if len(parts) < 4 || parts[1] != "api" || parts[2] != "v1" {
            c.Next()
            return
        }

        serviceName := parts[3]
        
        // 检查是否是第三方服务
        if strings.HasPrefix(serviceName, "thirdparty-") {
            appName := strings.TrimPrefix(serviceName, "thirdparty-")
            app, err := database.GetThirdPartyAppByName(appName)
            if err != nil {
                utils.ErrorResponse(c, http.StatusNotFound, "Third-party service not found")
                c.Abort()
                return
            }

            // 查找匹配的端点
            endpoint, err := database.FindMatchingEndpoint(app.AppID, c.Request.Method, strings.Join(parts[4:], "/"))
            if err != nil {
                utils.ErrorResponse(c, http.StatusNotFound, "API endpoint not found")
                c.Abort()
                return
            }

            // 检查端点认证要求
            if endpoint.AuthRequired {
                if !isAuthenticated(c) {
                    utils.ErrorResponse(c, http.StatusUnauthorized, "Authentication required for this endpoint")
                    c.Abort()
                    return
                }
            }

            // 创建反向代理
            target, err := url.Parse(endpoint.TargetURL)
            if err != nil {
                utils.ErrorResponse(c, http.StatusInternalServerError, "Invalid target URL")
                c.Abort()
                return
            }

            proxy := httputil.NewSingleHostReverseProxy(target)
            proxy.ModifyResponse = func(resp *http.Response) error {
                // 添加代理头信息
                resp.Header.Set("X-Proxy-Gateway", "microservice-gateway")
                resp.Header.Set("X-Upstream-Service", appName)
                return nil
            }

            // 设置超时
            timeout := time.Duration(endpoint.Timeout) * time.Second
            httpClient := &http.Client{Timeout: timeout}
            proxy.Transport = httpClient.Transport

            // 执行代理
            proxy.ServeHTTP(c.Writer, c.Request)
            c.Abort()
            return
        }

        c.Next()
    }
}

// 辅助函数
func checkRateLimit(appID string, limit int) bool {
    // 实现基于Redis或内存的速率限制
    // 这里简化实现
    return true
}

func isAuthenticated(c *gin.Context) bool {
    _, exists := c.Get("app_id")
    return exists
}
```

## 4. 扩展数据库操作 (database/third_party.go)

```go
package database

import (
    "microservice-gateway/models"
    "time"

    "gorm.io/gorm"
)

// ThirdPartyApp 相关操作
func CreateThirdPartyApp(app *models.ThirdPartyApp) error {
    return DB.Create(app).Error
}

func GetThirdPartyAppByID(appID string) (*models.ThirdPartyApp, error) {
    var app models.ThirdPartyApp
    err := DB.Where("app_id = ?", appID).First(&app).Error
    return &app, err
}

func GetThirdPartyAppByName(appName string) (*models.ThirdPartyApp, error) {
    var app models.ThirdPartyApp
    err := DB.Where("app_name = ?", appName).First(&app).Error
    return &app, err
}

func GetThirdPartyAppByCredentials(appID, appSecret string) (*models.ThirdPartyApp, error) {
    var app models.ThirdPartyApp
    err := DB.Where("app_id = ? AND app_secret = ?", appID, appSecret).First(&app).Error
    return &app, err
}

func GetThirdPartyAppByAPIKey(apiKey string) (*models.ThirdPartyApp, error) {
    var app models.ThirdPartyApp
    err := DB.Where("api_key = ?", apiKey).First(&app).Error
    return &app, err
}

func GetThirdPartyAppByToken(token string) (*models.ThirdPartyApp, error) {
    // 简化实现，实际应该解析JWT
    var app models.ThirdPartyApp
    err := DB.Where("api_key = ?", token).First(&app).Error // 临时实现
    return &app, err
}

func DeleteThirdPartyApp(appID string) error {
    return DB.Where("id = ?", appID).Delete(&models.ThirdPartyApp{}).Error
}

// APIEndpoint 相关操作
func CreateAPIEndpoint(endpoint *models.APIEndpoint) error {
    return DB.Create(endpoint).Error
}

func GetEndpointsByAppID(appID string) ([]models.APIEndpoint, error) {
    var endpoints []models.APIEndpoint
    err := DB.Where("app_id = ?", appID).Order("created_at DESC").Find(&endpoints).Error
    return endpoints, err
}

func FindMatchingEndpoint(appID, method, path string) (*models.APIEndpoint, error) {
    var endpoint models.APIEndpoint
    err := DB.Where("app_id = ? AND method = ? AND path = ?", appID, method, path).First(&endpoint).Error
    return &endpoint, err
}

func UpdateEndpoint(endpoint *models.APIEndpoint) error {
    return DB.Save(endpoint).Error
}

func DeleteEndpoint(endpointID string) error {
    return DB.Where("id = ?", endpointID).Delete(&models.APIEndpoint{}).Error
}
```

## 5. 更新路由配置 (api/routes.go)

```go
// 在SetupRoutes函数中添加第三方相关路由
func SetupRoutes(router *gin.Engine, cfg *config.Config, serviceHandler *handlers.ServiceHandler, thirdPartyHandler *handlers.ThirdPartyHandler) {
    // ... 原有代码 ...
    
    // 第三方服务路由组
    thirdparty := v1.Group("/thirdparty")
    {
        thirdparty.POST("/register", thirdPartyHandler.RegisterThirdParty)
        thirdparty.POST("/auth", thirdPartyHandler.AuthenticateThirdParty)
        
        // 需要认证的管理路由
        managed := thirdparty.Group("/:app_id")
        managed.Use(middleware.ThirdPartyAuth())
        {
            managed.POST("/endpoints", thirdPartyHandler.AddAPIEndpoint)
            managed.GET("/endpoints", thirdPartyHandler.GetAppEndpoints)
            managed.GET("/info", thirdPartyHandler.GetAppInfo)
        }
    }
    
    // 添加代理中间件（在所有路由之前）
    router.Use(middleware.ProxyMiddleware())
}
```

## 6. 使用示例

### 第三方应用注册
```bash
curl -X POST http://localhost:8080/api/v1/thirdparty/register \
  -H "Content-Type: application/json" \
  -d '{
    "app_name": "my-user-app",
    "vendor": "ACME Corp",
    "contact_email": "dev@acme.com",
    "description": "User management application",
    "base_url": "https://api.acme.com/v1",
    "health_url": "https://api.acme.com/health",
    "webhook_url": "https://webhook.acme.com/notifications",
    "required_apis": ["/users", "/users/*", "/health"]
  }'
```

### 配置API端点
```bash
curl -X POST http://localhost:8080/api/v1/thirdparty/{app_id}/endpoints \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/users",
    "method": "GET",
    "target_url": "https://api.acme.com/v1/users",
    "description": "Get user list",
    "rate_limit": 100,
    "auth_required": true,
    "timeout": 30
  }'
```

### 通过网关访问第三方服务
```bash
# 通过网关代理访问
curl http://localhost:8080/api/v1/thirdparty-my-user-app/users \
  -H "X-API-Key: {api_key}"

# 或使用Bearer Token
curl http://localhost:8080/api/v1/thirdparty-my-user-app/users \
  -H "Authorization: Bearer {token}"
```

这个方案提供了完整的第三方应用注册、认证、代理访问功能，支持灵活的API端点配置和安全管理。