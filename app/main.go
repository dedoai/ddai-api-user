package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	fmt.Printf("Received request: %+v\n", request)

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
		}
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
	fmt.Println("Handling GET user profile request")

	username := strings.TrimPrefix(request.Path, "/account/")
	if username == "" {
		fmt.Println("Username is required")
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       `{"error": "Username is required"}`,
		}, nil
	}

	accessToken, err := getKeycloakAdminToken()
	if err != nil {
		fmt.Printf("Failed to get admin token: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to get admin token"}`,
		}, nil
	}

	user, err := getUserByUsername(accessToken, username)
	if err != nil {
		fmt.Printf("Failed to get user: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to get user: %v"}`, err.Error()),
		}, nil
	}

	fmt.Printf("User profile retrieved: %+v\n", user)
	return respondWithJSON(user, 200)
}

func handleLogin(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	fmt.Println("Handling login request")

	if request.HTTPMethod != "POST" {
		fmt.Println("Method not allowed")
		return events.APIGatewayProxyResponse{
			StatusCode: 405,
			Body:       `{"error": "Method not allowed"}`,
		}, nil
	}

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	err := json.Unmarshal([]byte(request.Body), &credentials)
	if err != nil {
		fmt.Printf("Invalid request body: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       `{"error": "Invalid request body"}`,
		}, nil
	}

	realm := os.Getenv("KEYCLOAK_REALM")
	clientSecret := os.Getenv("CLIENT_SECRET")

	form := url.Values{}
	form.Set("client_id", "web-app")
	form.Set("client_secret", clientSecret)
	form.Set("grant_type", "password")
	form.Set("username", credentials.Username)
	form.Set("password", credentials.Password)

	req, err := http.NewRequest("POST", fmt.Sprintf("https://sso.dev.dedoai.org/realms/%s/protocol/openid-connect/token", realm), strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Printf("Failed to create request: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to create request"}`,
		}, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to get token: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to get token"}`,
		}, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read response: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to read response"}`,
		}, nil
	}

	fmt.Printf("Received response: %s\n", string(body))

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		fmt.Printf("Failed to parse token response: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to parse token response"}`,
		}, nil
	}

	fmt.Printf("Login successful, access token: %s\n", tokenResponse.AccessToken)
	return respondWithJSON(map[string]string{
		"status":       "success",
		"access_token": tokenResponse.AccessToken,
	}, 200)
}

func handleRegister(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	fmt.Println("Handling registration request")

	if request.HTTPMethod != "POST" {
		fmt.Println("Method not allowed")
		return events.APIGatewayProxyResponse{
			StatusCode: 405,
			Body:       `{"error": "Method not allowed"}`,
		}, nil
	}

	var userData struct {
		Username  string `json:"username"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Phone     string `json:"phone"`
		Password  string `json:"password"`
	}
	err := json.Unmarshal([]byte(request.Body), &userData)
	if err != nil {
		fmt.Printf("Invalid request body: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       `{"error": "Invalid request body"}`,
		}, nil
	}

	accessToken, err := getKeycloakAdminToken()
	if err != nil {
		fmt.Printf("Failed to get admin token: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to get admin token"}`,
		}, nil
	}

	userID, err := createKeycloakUser(accessToken, userData)
	if err != nil {
		fmt.Printf("Failed to create user: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to create user: %v"}`, err.Error()),
		}, nil
	}

	fmt.Printf("User created successfully, user ID: %s\n", userID)
	return respondWithJSON(map[string]string{
		"status":  "success",
		"user_id": userID,
	}, 201)
}

func getKeycloakAdminToken() (string, error) {
	fmt.Println("Getting Keycloak admin token")

	adminUsername := os.Getenv("KEYCLOAK_ADMIN_USERNAME")
	adminPassword := os.Getenv("KEYCLOAK_ADMIN_PASSWORD")
	realm := os.Getenv("KEYCLOAK_REALM")

	requestBody := url.Values{}
	requestBody.Set("username", adminUsername)
	requestBody.Set("password", adminPassword)
	requestBody.Set("grant_type", "password")
	requestBody.Set("client_id", "admin-cli")

	req, err := http.NewRequest("POST", fmt.Sprintf("https://sso.dev.dedoai.org/realms/%s/protocol/openid-connect/token", realm), strings.NewReader(requestBody.Encode()))
	if err != nil {
		fmt.Printf("Failed to create request: %v\n", err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to get admin token: %v\n", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read response: %v\n", err)
		return "", err
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		fmt.Printf("Failed to parse token response: %v, body: %s\n", err, string(body))
		return "", fmt.Errorf("failed to parse token response: %v", string(body))
	}

	fmt.Println("Admin token retrieved successfully")
	return tokenResponse.AccessToken, nil
}

func createKeycloakUser(accessToken string, userData struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Phone     string `json:"phone"`
	Password  string `json:"password"`
}) (string, error) {
	fmt.Println("Creating Keycloak user")

	realm := os.Getenv("KEYCLOAK_REALM")

	userPayload := map[string]interface{}{
		"username":  userData.Email,
		"email":     userData.Email,
		"firstName": userData.FirstName,
		"lastName":  userData.LastName,
		"attributes": map[string][]string{
			"phone": {userData.Phone},
		},
		"enabled": true,
		"credentials": []map[string]interface{}{
			{
				"type":      "password",
				"value":     userData.Password,
				"temporary": false,
			},
		},
	}
	payloadBytes, err := json.Marshal(userPayload)
	if err != nil {
		fmt.Printf("Failed to marshal user payload: %v\n", err)
		return "", err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://sso.dev.dedoai.org/admin/realms/%s/users", realm), bytes.NewBuffer(payloadBytes))
	if err != nil {
		fmt.Printf("Failed to create request: %v\n", err)
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to create user: %v\n", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Failed to create user, status code: %d, response: %s\n", resp.StatusCode, string(body))
		return "", fmt.Errorf("failed to create user, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	location := resp.Header.Get("Location")
	userID := location[strings.LastIndex(location, "/")+1:]

	fmt.Printf("User created successfully, user ID: %s\n", userID)
	return userID, nil
}

func getUserByUsername(accessToken, username string) (map[string]interface{}, error) {
	fmt.Printf("Getting user by username: %s\n", username)

	realm := os.Getenv("KEYCLOAK_REALM")

	req, err := http.NewRequest("GET", fmt.Sprintf("https://sso.dev.dedoai.org/admin/realms/%s/users?username=%s", realm, url.QueryEscape(username)), nil)
	if err != nil {
		fmt.Printf("Failed to create request: %v\n", err)
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to get user: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Failed to get user, status code: %d, response: %s\n", resp.StatusCode, string(body))
		return nil, fmt.Errorf("failed to get user, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	var users []map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&users)
	if err != nil {
		fmt.Printf("Failed to decode user response: %v\n", err)
		return nil, err
	}

	if len(users) == 0 {
		fmt.Printf("User not found: %s\n", username)
		return nil, fmt.Errorf("user not found")
	}

	fmt.Printf("User retrieved successfully: %+v\n", users[0])
	return users[0], nil
}

func respondWithJSON(data interface{}, statusCode int) (events.APIGatewayProxyResponse, error) {
	body, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Failed to marshal response body: %v\n", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Internal Server Error"}`,
		}, nil
	}

	fmt.Printf("Responding with JSON: %s\n", string(body))
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
