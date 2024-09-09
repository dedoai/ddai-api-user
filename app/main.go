package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Nerzal/gocloak/v12"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
)

var (
	client       gocloak.GoCloak
	realm        string
	clientID     string
	clientSecret string
)

func init() {
	realm = os.Getenv("KEYCLOAK_REALM")
	clientID = "web-app"
	clientSecret = os.Getenv("CLIENT_SECRET")

	client = *gocloak.NewClient("https://sso.dev.dedoai.org")
}

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	switch request.HTTPMethod {
	case "GET":
		if strings.HasPrefix(request.Path, "/account/") {
			return handleGetUserProfile(request)
		}
	case "POST":
		if request.Path == "/v1/auth/signin" {
			return handleLogin(request)
		} else if request.Path == "/v1/auth/signup" {
			return handleRegister(request)
		} else if request.Path == "/v1/auth/reset-password" {
			return handleResetPassword(request)
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
		OTPToken string `json:"otp_token"`
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

	if credentials.OTPToken == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       `{"error": "OTP token is missing"}`,
		}, nil
	}

	fmt.Printf("%+v\n", jwt.AccessToken)

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
	otpSecret := attributes["otp_secret"][0]
	valid := totp.Validate(credentials.OTPToken, otpSecret)
	if !valid {
		return events.APIGatewayProxyResponse{
			StatusCode: 401,
			Body:       `{"error": "Invalid OTP token"}`,
		}, nil
	}

	return respondWithJSON(map[string]string{
		"status":       "success",
		"access_token": jwt.AccessToken,
	}, 200)
}

func handleRegister(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
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

	user := gocloak.User{
		Email:   gocloak.StringP(userData.Email),
		Enabled: gocloak.BoolP(true),
		Attributes: &map[string][]string{
			"phone":      {userData.Phone},
			"otp_secret": {key.Secret()},
		},
	}

	userID, err := client.CreateUser(
		context.Background(),
		token.AccessToken,
		realm,
		user,
	)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to create user: %v"}`, err.Error()),
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
