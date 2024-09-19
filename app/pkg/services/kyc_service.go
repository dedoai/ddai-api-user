package services

import (
	"context"
	"net/http"
	"time"

	"github.com/Nerzal/gocloak/v12"
	"github.com/dedoai/ddai-api-user/models"
)

type KycService interface {
	CreateApplicant(ctx context.Context, user *gocloak.User) (string, error)
	GetApplicantStatus(ctx context.Context, applicantID string) (string, error)
	UpdateApplicantData(ctx context.Context, applicantID string, data models.KycData) error
	HandleWebhook(ctx context.Context, payload []byte) error
}

type kycService struct {
	projectID  string
	secretKey  string
	apiBaseURL string
	httpClient *http.Client
}

func NewKycService(projectID, secretKey string) KycService {
	return &kycService{
		projectID:  projectID,
		secretKey:  secretKey,
		apiBaseURL: "https://api.sumsub.com",
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (k *kycService) CreateApplicant(ctx context.Context, user *gocloak.User) (string, error) {
	return "", nil
}

func (k *kycService) GetApplicantStatus(ctx context.Context, applicantID string) (string, error) {
	return "", nil
}

func (k *kycService) UpdateApplicantData(ctx context.Context, applicantID string, data models.KycData) error {
	return nil
}

func (k *kycService) HandleWebhook(ctx context.Context, payload []byte) error {
	return nil
}
