package controller

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/dedoai/ddai-api-user/models"
	"github.com/dedoai/ddai-api-user/pkg/services"
)

type Controller struct {
	service    services.UserService
	kycService services.KYCService
}

func NewController(service services.UserService, kycService services.KYCService) *Controller {
	return &Controller{
		service:    service,
		kycService: kycService,
	}
}

type IResponse struct {
	StatusCode  int         `json:"statusCode"`
	ErrorCode   string      `json:"errorCode,omitempty"`
	Description string      `json:"description,omitempty"`
	Data        interface{} `json:"data,omitempty"`
}

func RespondWithJSON(data interface{}, statusCode int, errorCode string, description string) (events.APIGatewayProxyResponse, error) {
	response := IResponse{
		StatusCode:  statusCode,
		ErrorCode:   errorCode,
		Description: description,
		Data:        data,
	}

	body, err := json.Marshal(response)
	if err != nil {
		log.Println("Error marshalling response:", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"statusCode":500,"errorCode":"INTERNAL_SERVER_ERROR","description":"Internal Server Error"}`,
		}, nil
	}
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":                     "application/json",
			"Access-Control-Allow-Origin":      "*",
			"Access-Control-Allow-Methods":     "GET,POST,OPTIONS",
			"Access-Control-Allow-Headers":     "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
			"Access-Control-Allow-Credentials": "true",
		},
		Body: string(body),
	}, nil
}

func (c *Controller) HandleGetUserProfile(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	username := strings.TrimPrefix(request.Path, "/account/")
	user, err := c.service.GetUserProfile(context.Background(), username)
	if err != nil {
		log.Println("Error in HandleGetUserProfile:", err)
		return RespondWithJSON(nil, 500, models.ErrInternalServer, "Failed to get user profile")
	}
	return RespondWithJSON(user, 200, "", "")
}

func (c *Controller) HandleResetPassword(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var resetData struct {
		Email       string `json:"email"`
		NewPassword string `json:"new_password"`
	}
	err := json.Unmarshal([]byte(request.Body), &resetData)
	if err != nil {
		return RespondWithJSON(nil, 400, models.ErrInvalidRequestBody, "Invalid request body")
	}
	err = c.service.ResetPassword(context.Background(), resetData.Email, resetData.NewPassword)
	if err != nil {
		log.Println("Error in HandleResetPassword:", err)
		return RespondWithJSON(nil, 500, models.ErrInternalServer, "Failed to reset password")
	}
	return RespondWithJSON(map[string]string{"status": "success"}, 200, "", "")
}

func (c *Controller) HandleLogin(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Captcha  string `json:"captcha"`
	}
	err := json.Unmarshal([]byte(request.Body), &credentials)
	if err != nil {
		return RespondWithJSON(nil, 400, models.ErrInvalidRequestBody, "Invalid request body")
	}
	jwt, err := c.service.Login(context.Background(), credentials.Email, credentials.Password)
	if err != nil {
		log.Println("Error in HandleLogin:", err)
		if customErr, ok := err.(*models.CustomError); ok {
			return RespondWithJSON(nil, 401, customErr.ErrorCode, customErr.Description)
		} else {
			return RespondWithJSON(nil, 500, models.ErrInternalServer, "Internal server error")
		}
	}
	return RespondWithJSON(map[string]string{
		"status":        "success",
		"access_token":  jwt.AccessToken,
		"refresh_token": jwt.RefreshToken,
		"expires_in":    strconv.Itoa(jwt.ExpiresIn),
	}, 200, "", "")
}

func (c *Controller) HandleSignup(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var userData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Captcha  string `json:"captcha"`
	}
	err := json.Unmarshal([]byte(request.Body), &userData)
	if err != nil {
		return RespondWithJSON(nil, 400, models.ErrInvalidRequestBody, "Invalid request body")
	}
	userID, err := c.service.Signup(context.Background(), userData.Email, userData.Password)
	if err != nil {
		log.Println("Error in HandleSignup:", err)
		if customErr, ok := err.(*models.CustomError); ok {
			return RespondWithJSON(nil, 500, customErr.ErrorCode, customErr.Description)
		} else {
			return RespondWithJSON(nil, 500, models.ErrInternalServer, "Internal server error")
		}
	}
	return RespondWithJSON(map[string]interface{}{
		"status":  "success",
		"user_id": userID,
	}, 201, "", "")
}

func (c *Controller) HandleSendOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	email := request.QueryStringParameters["email"]
	if email == "" {
		return RespondWithJSON(nil, 400, models.ErrMissingParameter, "Missing email parameter")
	}
	_, userID, err := c.service.SendOTP(context.Background(), email)
	if err != nil {
		log.Println("Error in HandleSendOTP:", err)
		return RespondWithJSON(nil, 500, models.ErrInternalServer, "Failed to send OTP")
	}
	return RespondWithJSON(map[string]string{
		"message": "OTP sent successfully",
		"user_id": userID,
	}, 200, "", "")
}

func (c *Controller) HandleSendSmsOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	phoneNumber := request.QueryStringParameters["phoneNumber"]
	userID := request.QueryStringParameters["userid"]
	if phoneNumber == "" {
		return RespondWithJSON(nil, 400, models.ErrMissingParameter, "Missing phone parameter")
	}
	err := c.service.SendSmsOTP(context.Background(), phoneNumber, userID)
	if err != nil {
		log.Println("Error in HandleSendSmsOTP:", err)
		return RespondWithJSON(nil, 500, models.ErrInternalServer, "Failed to send SMS OTP")
	}
	return RespondWithJSON(map[string]string{"message": "SMS OTP sent successfully"}, 200, "", "")
}

func (c *Controller) HandleVerifySmsOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var requestBody struct {
		PhoneNumber string `json:"phoneNumber"`
		OTPToken    string `json:"otpToken"`
		UserID      string `json:"userid"`
	}
	err := json.Unmarshal([]byte(request.Body), &requestBody)
	if err != nil {
		return RespondWithJSON(nil, 400, models.ErrInvalidRequestBody, "Invalid request body")
	}
	valid, err := c.service.VerifySmsOTP(context.Background(), requestBody.PhoneNumber, requestBody.OTPToken, requestBody.UserID)
	if err != nil {
		log.Println("Error in HandleVerifySmsOTP:", err)
		return RespondWithJSON(nil, 500, models.ErrInternalServer, "Failed to verify SMS OTP")
	}
	if !valid {
		return RespondWithJSON(nil, 400, models.ErrOTPValidationError, "Invalid SMS OTP")
	}
	return RespondWithJSON(map[string]string{"message": "SMS OTP verified successfully"}, 200, "", "")
}

func (c *Controller) HandleVerifyOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var requestBody struct {
		Email    string `json:"email"`
		OTPToken string `json:"otpToken"`
	}
	err := json.Unmarshal([]byte(request.Body), &requestBody)
	if err != nil {
		return RespondWithJSON(nil, 400, models.ErrInvalidRequestBody, "Invalid request body")
	}
	err = c.service.VerifyOTP(context.Background(), requestBody.Email, requestBody.OTPToken)
	if err != nil {
		log.Println("Error in HandleVerifyOTP:", err)
		if customErr, ok := err.(*models.CustomError); ok {
			return RespondWithJSON(nil, 400, customErr.ErrorCode, customErr.Description)
		} else {
			return RespondWithJSON(nil, 500, models.ErrInternalServer, "Failed to verify OTP")
		}
	}
	return RespondWithJSON(map[string]string{"message": "OTP verified successfully"}, 200, "", "")
}

func (c *Controller) HandleSumsubWebhook(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var webhookData map[string]interface{}
	err := json.Unmarshal([]byte(request.Body), &webhookData)
	if err != nil {
		return RespondWithJSON(nil, 200, models.ErrInvalidRequestBody, "Invalid JSON payload")
	}

	eventType, ok := webhookData["type"].(string)
	if !ok {
		return RespondWithJSON(nil, 200, models.ErrInvalidRequestBody, "Missing or invalid 'type' field")
	}

	switch eventType {
	case "applicantReviewed":
		var applicantReviewed services.ApplicantReviewed
		err := json.Unmarshal([]byte(request.Body), &applicantReviewed)
		if err != nil {
			return RespondWithJSON(nil, 200, models.ErrInvalidRequestBody, "Invalid 'applicantReviewed' payload")
		}
		err = c.kycService.ProcessApplicantReviewed(context.Background(), applicantReviewed)
		if err != nil {
			log.Println("Error in ProcessApplicantReviewed:", err)
			return RespondWithJSON(nil, 200, models.ErrKYCProcessError, err.Error())
		}
	case "applicantCreated":
		var applicantCreated services.ApplicantCreated
		err := json.Unmarshal([]byte(request.Body), &applicantCreated)
		if err != nil {
			return RespondWithJSON(nil, 200, models.ErrInvalidRequestBody, "Invalid 'applicantCreated' payload")
		}
		err = c.kycService.ProcessApplicantCreated(context.Background(), applicantCreated)
		if err != nil {
			log.Println("Error in ProcessApplicantCreated:", err)
			return RespondWithJSON(nil, 200, models.ErrKYCProcessError, err.Error())
		}
	case "applicantWorkflowCompleted":
		var workflowCompleted services.ApplicantWorkflowCompleted
		err := json.Unmarshal([]byte(request.Body), &workflowCompleted)
		if err != nil {
			return RespondWithJSON(nil, 200, models.ErrInvalidRequestBody, "Invalid 'applicantWorkflowCompleted' payload")
		}
		err = c.kycService.ProcessWorkflowCompleted(context.Background(), workflowCompleted)
		if err != nil {
			log.Println("Error in ProcessWorkflowCompleted:", err)
			return RespondWithJSON(nil, 200, models.ErrKYCProcessError, err.Error())
		}
	default:
		return RespondWithJSON(nil, 200, models.ErrUnsupportedEventType, "Unsupported event type")
	}

	return RespondWithJSON(map[string]string{"status": "success"}, 200, "", "")
}
