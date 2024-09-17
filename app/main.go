package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v12"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
)

var (
	client                gocloak.GoCloak
	realm                 string
	clientID              string
	clientSecret          string
	twilioAccountSeed     string
	twilioAccountToken    string
	twilioSmsSenderNumber string
)

func init() {
	realm = os.Getenv("KEYCLOAK_REALM")
	clientID = "web-app"
	clientSecret = os.Getenv("CLIENT_SECRET")
	twilioAccountSeed = os.Getenv("TWILIO_ACCOUNT_SEED")
	twilioAccountToken = os.Getenv("TWILIO_ACCOUNT_TOKEN")
	twilioSmsSenderNumber = os.Getenv("TWILIO_SMS_SENDER_NUMBER")

	client = *gocloak.NewClient("https://sso.dev.dedoai.org")
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	switch request.HTTPMethod {
	case "GET":
		if strings.HasPrefix(request.Path, "/account/") {
			return handleGetUserProfile(request)
		} else if request.Path == "/v1/auth/otp/email" {
			return handleSendOTP(request)
		} else if request.Path == "/v1/auth/otp/sms" {
			return handleSendSmsOTP(request)
		}
	case "POST":
		if request.Path == "/v1/auth/signin" {
			return handleLogin(request)
		} else if request.Path == "/v1/auth/signup" {
			return handleSignup(request)
		} else if request.Path == "/v1/auth/reset-password" {
			return handleResetPassword(request)
		} else if request.Path == "/v1/auth/otp/email" {
			return handleVerifyOTP(request)
		} else if request.Path == "/v1/auth/otp/sms" {
			return handleVerifySmsOTP(request)
		}
	case "OPTIONS":
		return respondWithJSON(nil, 200)
	default:
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
			Body:       `{"error": "Endpoint not found"}`,
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 404,
		Body:       `{"error": "Endpoint not found"}`,
	}, nil
}

func handleSendOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	email := request.QueryStringParameters["email"]
	if email == "" {
		return respondWithJSON(map[string]string{"error": "Missing email parameter"}, 400)
	}

	otpToken := generateOTP(6)

	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Failed to login as admin"}, 500)
	}

	users, err := client.GetUsers(context.Background(), token.AccessToken, realm, gocloak.GetUsersParams{
		Email: gocloak.StringP(email),
	})
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Failed to get user by email"}, 500)
	}

	var userID string
	if len(users) == 0 {
		user := gocloak.User{
			Email:   gocloak.StringP(email),
			Enabled: gocloak.BoolP(true),
			Attributes: &map[string][]string{
				"draft": {"true"},
			},
		}
		userID, err = client.CreateUser(context.Background(), token.AccessToken, realm, user)
		if err != nil {
			return respondWithJSON(map[string]string{"error": "Failed to create user"}, 500)
		}
	} else {
		userID = *users[0].ID
	}

	err = saveOTPInKeycloak(email, otpToken, userID)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Failed to save OTP in Keycloak"}, 500)
	}

	err = sendOTPEmail(email, otpToken)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Failed to send OTP email"}, 500)
	}

	return respondWithJSON(map[string]string{"message": "OTP sent successfully"}, 200)
}

func handleSendSmsOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	phone := request.QueryStringParameters["phone"]
	userID := request.QueryStringParameters["userid"]
	if phone == "" {
		return respondWithJSON(map[string]string{"error": "Missing phone parameter"}, 400)
	}

	otpToken := generateOTP(6)

	err := saveSmsOTPInKeycloak(phone, otpToken, userID)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Failed to save SMS OTP in Keycloak"}, 500)
	}

	return respondWithJSON(map[string]string{"message": "SMS OTP sent successfully"}, 200)
}

func handleVerifySmsOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var requestBody struct {
		Phone    string `json:"phone"`
		OTPToken string `json:"otpToken"`
		UserID   string `json:"userid"`
	}

	err := json.Unmarshal([]byte(request.Body), &requestBody)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Invalid request body"}, 400)
	}

	phone := requestBody.Phone
	otpToken := requestBody.OTPToken
	userID := requestBody.UserID

	if phone == "" || otpToken == "" {
		return respondWithJSON(map[string]string{"error": "Missing phone or otpToken field"}, 400)
	}

	valid, err := verifySmsOTPFromKeycloak(phone, otpToken, userID)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Failed to verify SMS OTP"}, 500)
	}

	if !valid {
		return respondWithJSON(map[string]string{"error": "Invalid SMS OTP"}, 400)
	}

	err = removeSmsOTPFromKeycloak(phone, userID)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Failed to remove SMS OTP from Keycloak"}, 500)
	}

	return respondWithJSON(map[string]string{"message": "SMS OTP verified successfully"}, 200)
}

func handleVerifyOTP(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var requestBody struct {
		Email    string `json:"email"`
		OTPToken string `json:"otpToken"`
	}

	err := json.Unmarshal([]byte(request.Body), &requestBody)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Invalid request body"}, 400)
	}

	email := requestBody.Email
	otpToken := requestBody.OTPToken

	if email == "" || otpToken == "" {
		return respondWithJSON(map[string]string{"error": "Missing email or otp_token field"}, 400)
	}

	savedOTPToken, userID, err := getOTPFromKeycloak(email)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Failed to retrieve OTP from Keycloak"}, 500)
	}

	if otpToken != savedOTPToken {
		return respondWithJSON(map[string]string{"error": "Invalid OTP token"}, 400)
	}

	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "failed to login as admin"}, 400)
	}

	err = updateUserAttribute(token, userID, "validated_mail_otp", "true")
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Failed to update user attribute"}, 500)
	}

	err = removeOTPFromKeycloak(userID)
	if err != nil {
		return respondWithJSON(map[string]string{"error": "Failed to remove OTP from Keycloak"}, 500)
	}

	return respondWithJSON(map[string]string{"message": "OTP verified successfully"}, 200)
}

func generateOTP(length int) string {
	rand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	otp := make([]byte, length)
	for i := 0; i < length; i++ {
		otp[i] = digits[rand.Intn(len(digits))]
	}
	return string(otp)
}

func saveOTPInKeycloak(email, otpToken, userID string) error {
	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return fmt.Errorf("failed to login as admin: %v", err)
	}

	err = updateUserAttribute(token, userID, "mail_otp", otpToken)
	if err != nil {
		return fmt.Errorf("failed to update user attributes: %v", err)
	}

	err = updateUserAttribute(token, userID, "validated_mail_otp", "false")
	if err != nil {
		return fmt.Errorf("failed to update user attributes: %v", err)
	}

	return nil
}

func getOTPFromKeycloak(email string) (string, string, error) {
	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return "", "", fmt.Errorf("failed to login as admin: %v", err)
	}

	users, err := client.GetUsers(context.Background(), token.AccessToken, realm, gocloak.GetUsersParams{
		Email: gocloak.StringP(email),
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to get user by email: %v", err)
	}

	if len(users) == 0 {
		return "", "", fmt.Errorf("user not found with email: %s", email)
	}

	attributes := *users[0].Attributes
	if otpToken, ok := attributes["mail_otp"]; ok && len(otpToken) > 0 {
		return otpToken[0], *users[0].ID, nil
	}

	return "", "", fmt.Errorf("otp token not found for email: %s", email)
}

func removeOTPFromKeycloak(userID string) error {
	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return fmt.Errorf("failed to login as admin: %v", err)
	}

	err = updateUserAttribute(token, userID, "mail_otp", "")
	if err != nil {
		return fmt.Errorf("failed to remove otp token from user attributes: %v", err)
	}

	return nil
}

func updateUserAttribute(token *gocloak.JWT, userID, attributeKey, attributeValue string) error {
	user, err := client.GetUserByID(context.Background(), token.AccessToken, realm, userID)
	if err != nil {
		return fmt.Errorf("failed to get user by ID: %v", err)
	}

	attributes := user.Attributes
	if attributes == nil {
		attributes = &map[string][]string{}
	}

	if attributeValue == "" {
		delete(*attributes, attributeKey)
	} else {
		(*attributes)[attributeKey] = []string{attributeValue}
	}

	err = client.UpdateUser(context.Background(), token.AccessToken, realm, gocloak.User{
		ID:         &userID,
		Email:      user.Email,
		FirstName:  user.FirstName,
		LastName:   user.LastName,
		Attributes: attributes,
	})
	if err != nil {
		return fmt.Errorf("failed to update user attributes: %v", err)
	}

	return nil
}

func saveSmsOTPInKeycloak(phone, otpToken, userID string) error {
	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return fmt.Errorf("failed to login as admin: %v", err)
	}

	err = updateUserAttribute(token, userID, "phone", phone)
	if err != nil {
		return fmt.Errorf("failed to update user attributes: %v", err)
	}

	err = updateUserAttribute(token, userID, "sms_otp", otpToken)
	if err != nil {
		return fmt.Errorf("failed to update user attributes: %v", err)
	}

	err = updateUserAttribute(token, userID, "validated_sms_otp", "false")
	if err != nil {
		return fmt.Errorf("failed to update user attributes: %v", err)
	}

	return nil
}

func verifySmsOTPFromKeycloak(phone, otpToken, userID string) (bool, error) {
	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return false, fmt.Errorf("failed to login as admin: %v", err)
	}

	if err != nil {
		fmt.Println(err)
		return false, fmt.Errorf("failed to get user by phone number: %v", err)
	}

	storedOTP, _, err := getSmsOTPFromKeycloak(phone, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get sms otp from keycloak: %v", err)
	}

	if storedOTP == otpToken {
		err = updateUserAttribute(token, userID, "validated_sms_otp", "true")
		if err != nil {
			return false, fmt.Errorf("failed to update user attributes: %v", err)
		}
		return true, nil
	}

	return false, nil
}

func removeSmsOTPFromKeycloak(phone, userID string) error {
	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return fmt.Errorf("failed to login as admin: %v", err)
	}

	err = updateUserAttribute(token, userID, "sms_otp", "")
	if err != nil {
		return fmt.Errorf("failed to remove sms otp from user attributes: %v", err)
	}

	return nil
}

func getSmsOTPFromKeycloak(phone, userID string) (string, string, error) {
	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return "", "", fmt.Errorf("failed to login as admin: %v", err)
	}

	user, err := client.GetUserByID(context.Background(), token.AccessToken, realm, userID)
	if err != nil {
		fmt.Println(err)
		return "", "", fmt.Errorf("failed to get user by ID: %v", err)
	}

	attributes := *user.Attributes
	if otpToken, ok := attributes["sms_otp"]; ok && len(otpToken) > 0 {
		return otpToken[0], userID, nil
	}

	return "", "", fmt.Errorf("sms otp token not found for phone number: %s", phone)
}

func sendSmsOTP(phone, otpToken string) error {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: twilioAccountSeed,
		Password: twilioAccountToken,
	})

	params := &twilioApi.CreateMessageParams{}
	params.SetTo(phone)
	params.SetFrom("+17754060300")
	params.SetBody("Your OTP is: " + otpToken)

	resp, err := client.Api.CreateMessage(params)
	if err != nil {
		return fmt.Errorf("error sending SMS message: %v", err)
	}

	fmt.Println("resp", resp.Body)

	return nil
}

func sendOTPEmail(email, otpToken string) error {
	from := mail.NewEmail("Dedo OTP token", "web@dedoai.org")
	to := mail.NewEmail("", email)

	templateID := "d-a1088449da3a498d902679a2cee9b49f"

	message := mail.NewV3Mail()
	message.SetFrom(from)
	message.SetTemplateID(templateID)

	p := mail.NewPersonalization()
	p.AddTos(to)
	p.SetDynamicTemplateData("otp_token", otpToken)
	message.AddPersonalizations(p)

	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))

	_, err := client.Send(message)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

func handleGetUserProfile(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	username := strings.TrimPrefix(request.Path, "/account/")
	if username == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       `{"error": "Username is required"}`,
		}, nil
	}

	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to get admin token"}`,
		}, nil
	}

	users, err := client.GetUsers(
		context.Background(),
		token.AccessToken,
		realm,
		gocloak.GetUsersParams{
			Email: gocloak.StringP(username),
		},
	)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to get user: %v"}`, err.Error()),
		}, nil
	}

	if len(users) == 0 {
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
			Body:       `{"error": "User not found"}`,
		}, nil
	}

	return respondWithJSON(users[0], 200)
}

func handleResetPassword(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var resetData struct {
		Email       string `json:"email"`
		NewPassword string `json:"new_password"`
	}
	err := json.Unmarshal([]byte(request.Body), &resetData)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       `{"error": "Invalid request body"}`,
		}, nil
	}

	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to get admin token"}`,
		}, nil
	}

	users, err := client.GetUsers(
		context.Background(),
		token.AccessToken,
		realm,
		gocloak.GetUsersParams{
			Email: gocloak.StringP(resetData.Email),
		},
	)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to get user: %v"}`, err.Error()),
		}, nil
	}

	if len(users) == 0 {
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
			Body:       `{"error": "User not found"}`,
		}, nil
	}

	userID := *users[0].ID
	err = client.SetPassword(
		context.Background(),
		token.AccessToken,
		userID,
		realm,
		resetData.NewPassword,
		false,
	)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to reset password: %v"}`, err.Error()),
		}, nil
	}

	return respondWithJSON(map[string]string{
		"status": "success",
	}, 200)
}

func handleLogin(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := json.Unmarshal([]byte(request.Body), &credentials)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       `{"error": "Invalid request body"}`,
		}, nil
	}

	jwt, err := client.Login(
		context.Background(),
		clientID,
		clientSecret,
		realm,
		credentials.Email,
		credentials.Password,
	)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 401,
			Body:       `{"error": "Invalid credentials"}`,
		}, nil
	}

	token, _ := jwt5.Parse(jwt.AccessToken, func(token *jwt5.Token) (interface{}, error) {
		return nil, nil
	})

	claims, ok := token.Claims.(jwt5.MapClaims)
	if !ok {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to extract JWT claims"}`,
		}, nil
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to extract 'sub' claim from JWT token"}`,
		}, nil
	}

	user, err := client.GetUserByID(
		context.Background(),
		jwt.AccessToken,
		realm,
		sub,
	)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to get user"}`,
		}, nil
	}

	attributes := *user.Attributes
	validatedMailOTP, ok := attributes["validated_mail_otp"]
	if !ok || len(validatedMailOTP) == 0 || validatedMailOTP[0] != "true" {
		return events.APIGatewayProxyResponse{
			StatusCode: 401,
			Body:       `{"error": "Email OTP not validated"}`,
		}, nil
	}

	return respondWithJSON(map[string]string{
		"status":       "success",
		"access_token": jwt.AccessToken,
	}, 200)
}

func handleSignup(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var userData struct {
		Email    string `json:"email"`
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}
	err := json.Unmarshal([]byte(request.Body), &userData)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       `{"error": "Invalid request body"}`,
		}, nil
	}

	token, err := client.LoginAdmin(context.Background(), os.Getenv("KEYCLOAK_ADMIN_USERNAME"), os.Getenv("KEYCLOAK_ADMIN_PASSWORD"), realm)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to get admin token"}`,
		}, nil
	}

	users, err := client.GetUsers(
		context.Background(),
		token.AccessToken,
		realm,
		gocloak.GetUsersParams{
			Email: gocloak.StringP(userData.Email),
		},
	)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to get user: %v"}`, err.Error()),
		}, nil
	}

	if len(users) == 0 {
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
			Body:       `{"error": "User not found"}`,
		}, nil
	}

	userID := *users[0].ID

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Your App Name",
		AccountName: userData.Email,
	})
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to generate OTP secret"}`,
		}, nil
	}

	err = updateUserAttribute(token, userID, "phone", userData.Phone)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to update user phone: %v"}`, err.Error()),
		}, nil
	}

	err = updateUserAttribute(token, userID, "otp_secret", key.Secret())
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to update user otp_secret: %v"}`, err.Error()),
		}, nil
	}

	err = updateUserAttribute(token, userID, "draft", "")
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to update user draft attribute: %v"}`, err.Error()),
		}, nil
	}

	err = client.SetPassword(
		context.Background(),
		token.AccessToken,
		userID,
		realm,
		userData.Password,
		false,
	)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to set password: %v"}`, err.Error()),
		}, nil
	}

	return respondWithJSON(map[string]interface{}{
		"status":     "success",
		"user_id":    userID,
		"otp_url":    key.URL(),
		"otp_secret": key.Secret(),
	}, 201)
}

func respondWithJSON(data interface{}, statusCode int) (events.APIGatewayProxyResponse, error) {
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

func main() {
	lambda.Start(Handler)
}
