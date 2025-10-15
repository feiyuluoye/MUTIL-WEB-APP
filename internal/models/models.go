package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ServiceInfo 微服务信息
type ServiceInfo struct {
	ID              string    `json:"id" gorm:"primaryKey;type:varchar(36)"`
	Name            string    `json:"name" gorm:"not null;index"`
	Version         string    `json:"version"`
	Description     string    `json:"description"`
	BaseURL         string    `json:"base_url" gorm:"not null"`
	HealthURL       string    `json:"health_url"`
	Status          string    `json:"status" gorm:"default:'unknown'"`
	Metadata        string    `json:"metadata" gorm:"type:TEXT"` // JSON 格式的元数据
	LastHealthCheck time.Time `json:"last_health_check"`
	RegisteredAt    time.Time `json:"registered_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// BeforeCreate GORM 钩子：在创建前设置 ID 和时间戳
func (s *ServiceInfo) BeforeCreate(tx *gorm.DB) (err error) {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	now := time.Now()
	if s.RegisteredAt.IsZero() {
		s.RegisteredAt = now
	}
	s.UpdatedAt = now
	return nil
}

// BeforeUpdate GORM 钩子：在更新前设置 UpdatedAt
func (s *ServiceInfo) BeforeUpdate(tx *gorm.DB) (err error) {
	s.UpdatedAt = time.Now()
	return nil
}

// GetMetadata 返回 Metadata 的 map 形式（若为空返回空 map）
func (s *ServiceInfo) GetMetadata() map[string]string {
	var m map[string]string
	if s.Metadata == "" {
		return map[string]string{}
	}
	_ = json.Unmarshal([]byte(s.Metadata), &m)
	if m == nil {
		return map[string]string{}
	}
	return m
}

// SetMetadata 将 map 序列化并保存到 Metadata 字段
func (s *ServiceInfo) SetMetadata(m map[string]string) error {
	if m == nil {
		s.Metadata = ""
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	s.Metadata = string(b)
	return nil
}

// 可选：自定义表名（如需）
func (ServiceInfo) TableName() string {
	return "services"
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
	TotalServices     int `json:"total_services"`
	HealthyServices   int `json:"healthy_services"`
	UnhealthyServices int `json:"unhealthy_services"`
}
