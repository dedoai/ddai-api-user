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
	switch request.HTTPMethod {
	case "GET":
		if strings.HasPrefix(request.Path, "/account/") {
			return handleGetUserProfile(request)
		}
	case "POST":
		if request.Path == "/login" {
			return handleLogin(request)
		} else if request.Path == "/register" {
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
	username := strings.TrimPrefix(request.Path, "/account/")
	if username == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       `{"error": "Username is required"}`,
		}, nil
	}

	accessToken, err := getKeycloakAdminToken()
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to get admin token"}`,
		}, nil
	}

	user, err := getUserByUsername(accessToken, username)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to get user: %v"}`, err.Error()),
		}, nil
	}

	return respondWithJSON(user, 200)
}

func handleLogin(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	if request.HTTPMethod != "POST" {
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
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to create request"}`,
		}, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to get token"}`,
		}, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to read response"}`,
		}, nil
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to parse token response"}`,
		}, nil
	}

	return respondWithJSON(map[string]string{
		"status":       "success",
		"access_token": tokenResponse.AccessToken,
	}, 200)
}

func handleRegister(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	if request.HTTPMethod != "POST" {
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
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       `{"error": "Invalid request body"}`,
		}, nil
	}

	accessToken, err := getKeycloakAdminToken()
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Failed to get admin token"}`,
		}, nil
	}

	userID, err := createKeycloakUser(accessToken, userData)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "Failed to create user: %v"}`, err.Error()),
		}, nil
	}

	return respondWithJSON(map[string]string{
		"status":  "success",
		"user_id": userID,
	}, 201)
}

func getKeycloakAdminToken() (string, error) {
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
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", string(body))
	}

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
		return "", err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://sso.dev.dedoai.org/admin/realms/%s/users", realm), bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create user, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	location := resp.Header.Get("Location")
	userID := location[strings.LastIndex(location, "/")+1:]

	return userID, nil
}

func getUserByUsername(accessToken, username string) (map[string]interface{}, error) {
	realm := os.Getenv("KEYCLOAK_REALM")

	req, err := http.NewRequest("GET", fmt.Sprintf("https://sso.dev.dedoai.org/admin/realms/%s/users?username=%s", realm, url.QueryEscape(username)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user, status code: %d, response: %s", resp.StatusCode, string(body))
	}

	var users []map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&users)
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return users[0], nil
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
			"Content-Type": "application/json",
		},
		Body: string(body),
	}, nil
}

func main() {
	lambda.Start(Handler)
}
