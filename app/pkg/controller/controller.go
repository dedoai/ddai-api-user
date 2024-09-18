package controller

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/dedoai/ddai-api-user/pkg/services"
)

type Controller struct {
	service services.UserService
}

func NewController(service services.UserService) *Controller {
	return &Controller{
		service: service,
	}
}

func (c *Controller) HandleGetUserProfile(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	username := strings.TrimPrefix(request.Path, "/account/")
	user, err := c.service.GetUserProfile(context.Background(), username)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": err.Error()}, 500)
	}
	return RespondWithJSON(user, 200)
}

func (c *Controller) HandleResetPassword(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var resetData struct {
		Email       string `json:"email"`
		NewPassword string `json:"new_password"`
	}
	err := json.Unmarshal([]byte(request.Body), &resetData)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": "Invalid request body"}, 400)
	}
	err = c.service.ResetPassword(context.Background(), resetData.Email, resetData.NewPassword)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": err.Error()}, 500)
	}
	return RespondWithJSON(map[string]string{"status": "success"}, 200)
}

func (c *Controller) HandleLogin(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := json.Unmarshal([]byte(request.Body), &credentials)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": "Invalid request body"}, 400)
	}
	jwt, err := c.service.Login(context.Background(), credentials.Email, credentials.Password)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": "Invalid credentials"}, 401)
	}
	return RespondWithJSON(map[string]string{
		"status":       "success",
		"access_token": jwt.AccessToken,
	}, 200)
}

func (c *Controller) HandleSignup(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var userData struct {
		Email    string `json:"email"`
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}
	err := json.Unmarshal([]byte(request.Body), &userData)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": "Invalid request body"}, 400)
	}
	userID, otpSecret, err := c.service.Signup(context.Background(), userData.Email, userData.Phone, userData.Password)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": err.Error()}, 500)
	}
	return RespondWithJSON(map[string]interface{}{
		"status":     "success",
		"user_id":    userID,
		"otp_secret": otpSecret,
	}, 201)
}

func (c *Controller) HandleSendOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	email := request.QueryStringParameters["email"]
	if email == "" {
		return RespondWithJSON(map[string]string{"error": "Missing email parameter"}, 400)
	}
	err := c.service.SendOTP(context.Background(), email)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": err.Error()}, 500)
	}
	return RespondWithJSON(map[string]string{"message": "OTP sent successfully"}, 200)
}

func (c *Controller) HandleSendSmsOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	phone := request.QueryStringParameters["phone"]
	userID := request.QueryStringParameters["userid"]
	if phone == "" {
		return RespondWithJSON(map[string]string{"error": "Missing phone parameter"}, 400)
	}
	err := c.service.SendSmsOTP(context.Background(), phone, userID)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": err.Error()}, 500)
	}
	return RespondWithJSON(map[string]string{"message": "SMS OTP sent successfully"}, 200)
}

func (c *Controller) HandleVerifySmsOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var requestBody struct {
		Phone    string `json:"phone"`
		OTPToken string `json:"otpToken"`
		UserID   string `json:"userid"`
	}
	err := json.Unmarshal([]byte(request.Body), &requestBody)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": "Invalid request body"}, 400)
	}
	valid, err := c.service.VerifySmsOTP(context.Background(), requestBody.Phone, requestBody.OTPToken, requestBody.UserID)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": err.Error()}, 500)
	}
	if !valid {
		return RespondWithJSON(map[string]string{"error": "Invalid SMS OTP"}, 400)
	}
	return RespondWithJSON(map[string]string{"message": "SMS OTP verified successfully"}, 200)
}

func (c *Controller) HandleVerifyOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var requestBody struct {
		Email    string `json:"email"`
		OTPToken string `json:"otpToken"`
	}
	err := json.Unmarshal([]byte(request.Body), &requestBody)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": "Invalid request body"}, 400)
	}
	err = c.service.VerifyOTP(context.Background(), requestBody.Email, requestBody.OTPToken)
	if err != nil {
		return RespondWithJSON(map[string]string{"error": err.Error()}, 500)
	}
	return RespondWithJSON(map[string]string{"message": "OTP verified successfully"}, 200)
}

func RespondWithJSON(data interface{}, statusCode int) (events.APIGatewayProxyResponse, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Internal Server Error"}`,
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
