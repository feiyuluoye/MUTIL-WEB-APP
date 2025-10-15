package database

import (
	"fmt"
	"microservice-gateway/internal/models"
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
			"status":            status,
			"last_health_check": time.Now(),
			"updated_at":        time.Now(),
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
