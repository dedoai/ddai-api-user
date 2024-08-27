package main

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// Response è la struttura della risposta in JSON
type Response struct {
	Message string `json:"message"`
}

// Handler è la funzione che verrà invocata da AWS Lambda
func Handler(ctx context.Context) (events.APIGatewayProxyResponse, error) {
	// Creiamo un'istanza di Response con il messaggio "Hello, World!"
	resp := Response{
		Message: "Hello, World!",
	}

	// Convertiamo la risposta in JSON
	body, err := json.Marshal(resp)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       `{"error": "Internal Server Error"}`,
		}, nil
	}

	// Restituiamo la risposta corretta per API Gateway
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(body),
	}, nil
}

func main() {
	// lambda.Start lancia la funzione Lambda
	lambda.Start(Handler)
}
