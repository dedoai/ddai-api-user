package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

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

type ApplicantWorkflowCompleted struct {
	ApplicantID    string `json:"applicantId"`
	InspectionID   string `json:"inspectionId"`
	ApplicantType  string `json:"applicantType"`
	CorrelationID  string `json:"correlationId"`
	LevelName      string `json:"levelName"`
	SandboxMode    bool   `json:"sandboxMode"`
	ExternalUserID string `json:"externalUserId"`
	Type           string `json:"type"`
	ReviewResult   struct {
		ReviewAnswer     string   `json:"reviewAnswer"`
		RejectLabels     []string `json:"rejectLabels"`
		ReviewRejectType string   `json:"reviewRejectType"`
		ButtonIds        []string `json:"buttonIds"`
	} `json:"reviewResult"`
	ReviewStatus string `json:"reviewStatus"`
	CreatedAt    string `json:"createdAt"`
	CreatedAtMs  string `json:"createdAtMs"`
	ClientID     string `json:"clientId"`
}

type ApplicantDetails struct {
	ID                string          `json:"id"`
	CreatedAt         string          `json:"createdAt"`
	CreatedBy         string          `json:"createdBy"`
	Key               string          `json:"key"`
	ClientID          string          `json:"clientId"`
	InspectionID      string          `json:"inspectionId"`
	ExternalUserID    string          `json:"externalUserId"`
	SourceKey         string          `json:"sourceKey"`
	Info              ApplicantInfo   `json:"info"`
	Email             string          `json:"email"`
	Phone             string          `json:"phone"`
	ApplicantPlatform string          `json:"applicantPlatform"`
	Questionnaires    []Questionnaire `json:"questionnaires"`
	RiskLabels        RiskLabels      `json:"riskLabels"`
	Review            Review          `json:"review"`
	Lang              string          `json:"lang"`
	Type              string          `json:"type"`
}

type ApplicantInfo struct {
	FirstName      string `json:"firstName"`
	FirstNameEn    string `json:"firstNameEn"`
	LastName       string `json:"lastName"`
	LastNameEn     string `json:"lastNameEn"`
	DOB            string `json:"dob"`
	Gender         string `json:"gender"`
	PlaceOfBirth   string `json:"placeOfBirth"`
	PlaceOfBirthEn string `json:"placeOfBirthEn"`
	Country        string `json:"country"`
	Nationality    string `json:"nationality"`
	CountryOfBirth string `json:"countryOfBirth"`
	StateOfBirth   string `json:"stateOfBirth"`
}

type Questionnaire struct {
	ID       string   `json:"id"`
	Sections Sections `json:"sections"`
}

type Sections struct {
	AccountInformation AccountInformation `json:"accountInformation"`
	CompanyInformation CompanyInformation `json:"companyInformation"`
}

type AccountInformation struct {
	Items map[string]interface{} `json:"items"`
}

type CompanyInformation struct {
	Items map[string]interface{} `json:"items"`
}

type RiskLabels struct {
	AttemptID string   `json:"attemptId"`
	CreatedAt string   `json:"createdAt"`
	Device    []string `json:"device"`
}

type Review struct {
	ReviewID              string       `json:"reviewId"`
	AttemptID             string       `json:"attemptId"`
	AttemptCnt            int          `json:"attemptCnt"`
	ElapsedSincePendingMs int          `json:"elapsedSincePendingMs"`
	ElapsedSinceQueuedMs  int          `json:"elapsedSinceQueuedMs"`
	Reprocessing          bool         `json:"reprocessing"`
	LevelName             string       `json:"levelName"`
	LevelAutoCheckMode    interface{}  `json:"levelAutoCheckMode"`
	CreateDate            string       `json:"createDate"`
	ReviewDate            string       `json:"reviewDate"`
	ReviewResult          ReviewResult `json:"reviewResult"`
	ReviewStatus          string       `json:"reviewStatus"`
	Priority              int          `json:"priority"`
}

type ReviewResult struct {
	ReviewAnswer string `json:"reviewAnswer"`
}

type KYCService interface {
	ProcessApplicantCreated(ctx context.Context, applicant ApplicantCreated) error
	ProcessApplicantReviewed(ctx context.Context, applicant ApplicantReviewed) error
	ProcessWorkflowCompleted(ctx context.Context, workflowCompleted ApplicantWorkflowCompleted) error
}

type kycService struct {
	repo repository.UserRepository
}

func NewKYCService(repo repository.UserRepository) KYCService {
	return &kycService{
		repo: repo,
	}
}

func (s *kycService) ProcessApplicantCreated(ctx context.Context, applicant ApplicantCreated) error {
	user := gocloak.User{
		Username: &applicant.ExternalUserID,
		Enabled:  gocloak.BoolP(true),
		Attributes: &map[string][]string{
			"applicant_id": {applicant.ApplicantID},
			"kyc_status":   {"pending"},
		},
	}

	_, err := s.repo.CreateUser(ctx, "vpn", user)
	if err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	return nil
}

type AccessTokenResponse struct {
	Token   string             `json:"token"`
	UserID  string             `json:"userId"`
	Headers AccessTokenHeaders `json:"headers"`
}

type AccessTokenHeaders struct {
	XAppToken     string `json:"X-App-Token"`
	XAppAccessTs  int64  `json:"X-App-Access-Ts"`
	XAppAccessSig string `json:"X-App-Access-Sig"`
}

func (s *kycService) ProcessApplicantReviewed(ctx context.Context, applicant ApplicantReviewed) error {
	user, err := s.repo.GetUserByUsername(ctx, "vpn", applicant.ExternalUserID)
	if err != nil {
		return fmt.Errorf("failed to get user by ID: %v", err)
	}

	accessTokenURL := fmt.Sprintf("https://api.dedoai.org/kyc/access-token?method=GET&url=/resources/applicants/%s/one", applicant.ApplicantID)
	accessTokenReq, _ := http.NewRequest("GET", accessTokenURL, nil)
	accessTokenRes, err := http.DefaultClient.Do(accessTokenReq)
	if err != nil {
		return fmt.Errorf("failed to make access token request: %v", err)
	}
	defer accessTokenRes.Body.Close()

	accessTokenBody, err := io.ReadAll(accessTokenRes.Body)
	if err != nil {
		return fmt.Errorf("failed to read access token response: %v", err)
	}

	var accessTokenResponse AccessTokenResponse
	err = json.Unmarshal(accessTokenBody, &accessTokenResponse)
	if err != nil {
		return fmt.Errorf("failed to parse access token response: %v", err)
	}

	accessTs := strconv.FormatInt(accessTokenResponse.Headers.XAppAccessTs, 10)

	url := fmt.Sprintf("https://api.sumsub.com/resources/applicants/%s/one", applicant.ApplicantID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("X-App-Token", accessTokenResponse.Headers.XAppToken)
	req.Header.Add("X-App-Access-Ts", accessTs)
	req.Header.Add("X-App-Access-Sig", accessTokenResponse.Headers.XAppAccessSig)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make Sumsub API request: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read Sumsub API response: %v", err)
	}

	var applicantDetails ApplicantDetails
	err = json.Unmarshal(body, &applicantDetails)
	if err != nil {
		return fmt.Errorf("failed to parse Sumsub API response: %v", err)
	}

	var walletAddress string
	if len(applicantDetails.Questionnaires) > 0 {
		questionnaire := applicantDetails.Questionnaires[0]
		if items, ok := questionnaire.Sections.AccountInformation.Items["cryptoWalletAddress"]; ok {
			if value, ok := items.(map[string]interface{})["value"]; ok {
				walletAddress = value.(string)
			}
		}
	}

	fmt.Println("waller", walletAddress)

	mergedAttributes := mergeAttributes(user.Attributes, &map[string][]string{
		"kyc_status":     {applicant.ReviewStatus},
		"phone":          {applicantDetails.Phone},
		"dob":            {applicantDetails.Info.DOB},
		"gender":         {applicantDetails.Info.Gender},
		"place_of_birth": {applicantDetails.Info.PlaceOfBirth},
		"country":        {applicantDetails.Info.Country},
		"nationality":    {applicantDetails.Info.Nationality},
		"wallet_address": {walletAddress},
	})

	err = s.repo.UpdateUser(ctx, "vpn", gocloak.User{
		ID:         user.ID,
		Username:   user.Username,
		Email:      gocloak.StringP(applicantDetails.Email),
		FirstName:  gocloak.StringP(applicantDetails.Info.FirstName),
		LastName:   gocloak.StringP(applicantDetails.Info.LastName),
		Attributes: &mergedAttributes,
	})
	if err != nil {
		return fmt.Errorf("failed to update user attribute: %v", err)
	}

	return nil
}

func (s *kycService) ProcessWorkflowCompleted(ctx context.Context, workflowCompleted ApplicantWorkflowCompleted) error {
	return nil
}
