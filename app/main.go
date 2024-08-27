package main

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	if username, ok := request.PathParameters["username"]; ok {
		if username == "" {
			return events.APIGatewayProxyResponse{
				StatusCode: 404,
				Body:       `{"error": "User not found"}`,
			}, nil
		}
		return respondWithJSON(map[string]string{"username": username}, 200)
	}

	switch request.Path {
	case "/notifications":
		return respondWithJSON(map[string]string{"message": "Notifications endpoint"}, 200)

	case "/datasets":
		return respondWithJSON(map[string]string{"message": "Datasets endpoint"}, 200)

	case "/c4ds":
		return respondWithJSON(map[string]string{"message": "C4Ds endpoint"}, 200)

	default:
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
			Body:       `{"error": "Endpoint not found"}`,
		}, nil
	}
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
