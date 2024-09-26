package services

import (
	"context"
	"fmt"

	"github.com/Nerzal/gocloak/v12"
	"github.com/dedoai/ddai-api-user/pkg/repository"
)

type ApplicantReviewed struct {
	ApplicantID    string `json:"applicantId"`
	InspectionID   string `json:"inspectionId"`
	CorrelationID  string `json:"correlationId"`
	ExternalUserID string `json:"externalUserId"`
	LevelName      string `json:"levelName"`
	Type           string `json:"type"`
	ReviewResult   struct {
		ReviewAnswer string `json:"reviewAnswer"`
	} `json:"reviewResult"`
	ReviewStatus string `json:"reviewStatus"`
	CreatedAtMs  string `json:"createdAtMs"`
}

type ApplicantCreated struct {
	ApplicantID    string `json:"applicantId"`
	InspectionID   string `json:"inspectionId"`
	CorrelationID  string `json:"correlationId"`
	LevelName      string `json:"levelName"`
	ExternalUserID string `json:"externalUserId"`
	Type           string `json:"type"`
	SandboxMode    string `json:"sandboxMode"`
	ReviewStatus   string `json:"reviewStatus"`
	CreatedAtMs    string `json:"createdAtMs"`
	ClientID       string `json:"clientId"`
}

type KYCService interface {
	ProcessApplicantCreated(ctx context.Context, applicantID string) error
	ProcessApplicantReviewed(ctx context.Context, applicantID string, status string) error
}

type kycService struct {
	repo repository.UserRepository
}

func NewKYCService(repo repository.UserRepository) KYCService {
	return &kycService{
		repo: repo,
	}
}

func (s *kycService) ProcessApplicantCreated(ctx context.Context, applicantID string) error {
	user, err := s.repo.GetUserByID(ctx, applicantID)
	if err != nil {
		return fmt.Errorf("failed to get user by ID: %v", err)
	}

	mergedAttributes := mergeAttributes(user.Attributes, &map[string][]string{
		"kyc_status": {"pending"},
	})
	err = s.repo.UpdateUser(ctx, gocloak.User{
		ID:         user.ID,
		Email:      user.Email,
		Attributes: &mergedAttributes,
	})
	if err != nil {
		return fmt.Errorf("failed to update user attribute: %v", err)
	}

	return nil
}

func (s *kycService) ProcessApplicantReviewed(ctx context.Context, applicantID string, status string) error {
	user, err := s.repo.GetUserByID(ctx, applicantID)
	if err != nil {
		return fmt.Errorf("failed to get user by ID: %v", err)
	}

	mergedAttributes := mergeAttributes(user.Attributes, &map[string][]string{
		"kyc_status": {status},
	})
	err = s.repo.UpdateUser(ctx, gocloak.User{
		ID:         user.ID,
		Email:      user.Email,
		Attributes: &mergedAttributes,
	})
	if err != nil {
		return fmt.Errorf("failed to update user attribute: %v", err)
	}

	return nil
}
