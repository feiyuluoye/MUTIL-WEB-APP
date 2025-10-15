package registry

import (
	"encoding/json"
	"fmt"
	"microservice-gateway/internal/database"
	"microservice-gateway/internal/models"
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
	if existingService != nil && existingService.ID != "" {
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
