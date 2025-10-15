package handlers

import (
	"microservice-gateway/internal/database"
	"microservice-gateway/internal/models"
	"microservice-gateway/internal/registry"
	"microservice-gateway/internal/utils"
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

	utils.CreatedResponse(c, "Service registered successfully", service)
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
