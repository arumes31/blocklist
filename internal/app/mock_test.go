package app

import (
	"github.com/stretchr/testify/mock"
)

type MockWebhookService struct {
	mock.Mock
}

func (m *MockWebhookService) Close() {
	m.Called()
}

type MockGeoUpdater struct {
	mock.Mock
}

func (m *MockGeoUpdater) Start() {
	m.Called()
}

func (m *MockGeoUpdater) Close() {
	m.Called()
}

type MockScheduler struct {
	mock.Mock
}

func (m *MockScheduler) Start() {
	m.Called()
}

func (m *MockScheduler) Stop() {
	m.Called()
}
